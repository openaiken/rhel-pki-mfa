###########################################################
#
#	AUTHOR:	 Hayden Aiken
#	DATE:	 07 November 2023
#	PURPOSE: Read a DOD Root CA-Signed user certificate belonging to a user, and load the cert & mapping info into his/her AD account.
#
###########################################################
# Step 0: Get arguments or display help
###########################################################

#Get the CLI arguments
param(
    [string]$CertificateFilePath,
    [string]$ForceUsername = "",
    [switch]$SkipSmartCardCheck = $false,
    [switch]$ReadOnly = $false,
    [switch]$Help = $false
)

# Help menu function
function Show-Help {
    Write-Host "Usage: AD-User-Cert-Update.ps1 -Cert <FilePath> [-ForceUsername <String>] [-SkipSmartCardCheck] [-ReadOnly] [-Help]"
    Write-Host " Arguments:"
    Write-Host "  -CertificateFilePath <FilePath> : "
	Write-Host "  -Cert	<FilePath> :"
	Write-Host "			Path to certificate file (required)"
    Write-Host "  -ForceUsername <Username> :"
	Write-Host "			(optional) Override AD User lookup -- NOT RECOMMENDED! Should take user@domain or EDIPI@mil [sic]"
    Write-Host "  -SkipSmartCardCheck :"
	Write-Host "			(optional) Skip 'Smart Card Logon' usage support check (could be useful for cert-based SVC accounts)"
    Write-Host "  -ReadOnly :"
	Write-Host "			(optional) Set to read-only mode (all checks performed but no changes made)"
    Write-Host "  -Help	:"
	Write-Host "			Display this help message and exit."
}
if ($Help) {
    Show-Help
    exit
}

# Check if CertificateFilePath is provided
if (-not $CertificateFilePath) {
    Write-Host "ERROR: -Cert option is required."
    Show-Help
    exit 1
}
# Resolve relative path to absolute path
$CertificateFilePath = Convert-Path $CertificateFilePath
# Check if file exists
if (-not (Test-Path $CertificateFilePath -PathType Leaf)) {
    Write-Host "ERROR: Certificate file not found at ${CertificateFilePath}"
    Show-Help
    exit 1
}

###########################################################
# Step 1: Detect encoding and load certificate
###########################################################

function 1_LoadCert() {
	# Create a x509 certificate object and load the specified cert into it
	$Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
	$Certificate.Import("${CertificateFilePath}")
	return $Certificate
}

###########################################################
# Step 2: Validate certificate against the host's keystore
###########################################################

function 2_TestCert() {
	param ([Object]$Certificate)
	$certTestParams = @{
		Cert = $Certificate
		AllowUntrustedRoot = $false
		User = $true
	}
	# Make sure that the certificate is valid (signed by trusted CAs all the way to the root)
	$IsValid = Test-Certificate @certTestParams

	if (-not $IsValid) {
		Write-Host "ERROR: This certificate is not trusted by the host's certificate stores (i.e. it failed x509 signature validation checking)."
		exit
	} else {
		Write-Host "INFO: Certificate is valid. Proceeding."
	}
}
###########################################################
# Step 3: Check Extended Key Usage
###########################################################

# We need to make sure that the certificate provided supports Client Authentication, and Smart Card Logon.
# If either are not supported by this X509 Certificate, it needs to not be uploaded to the user account.

function 3_CheckEKU() {
	param ([Object]$Certificate)
	#Check ClientAuth
	if ( $Certificate | Where-Object { $_.EnhancedKeyUsageList.FriendlyName -eq "Client Authentication" } ) {
		Write-Host "INFO: Certificate supports Client Authentication."
	}
	else {
		Write-Host "ERROR: Certificate does not support Client Authentication."
		exit
	}
	#Check msSC Logon
	if (-not $SkipSmartCardCheck) {
		if ( $Certificate | Where-Object { $_.EnhancedKeyUsageList.FriendlyName -eq "Smart Card Logon" } ) {
			Write-Host "INFO: Certificate supports Smart Card Logon."
		}
		else {
			Write-Host "ERROR: Certificate does not support Smart Card Logon."
			exit
		}
	}
}

###########################################################
# Step 4: Lookup user in AD
###########################################################

function 4_FindUser() {
	param ([Object]$Certificate)
	$StrongMappingUsed = $false
	# Get the certificate's Issuser Distinguished Name, and remove whitespace between fields.
	$Issuer = $Certificate.GetIssuerName() -replace '(?<!\\),\s+', ','
	# Get the cert's serial number -- it's "raw" because we need to manipulate it.
	$RawSerial = $Certificate.GetSerialNumberString();

	# Split the serial into 2-character "words", reverse the order of the words, and put it back together as a string.
	[string[]]$snWordArr = $($RawSerial -split '(\w{2})')
	$snWordArr = $snWordArr | ForEach-Object { [string]$_ }
	[System.Array]::Reverse($snWordArr)
	$ReversedSerial = -join $snWordArr

	# Generate the string that serves as the value of altSecurityIdentities, used for Strong Mapping. The format here is standardized.
	$IssuerSerial = "X509:<I>${Issuer}<SR>${ReversedSerial}"


	if ($ForceUsername -ne "") {
		#
		# This section runs if a username was passed in as a CLI argument. We check AD for a matching logon name.
		# If we find a match, see if the Strong Mapping string is already good. If not we'll update it, but if so 
		# we just proceed as if it was strong mapped.
		#
		Write-Host "INFO: Override provided. Trying lookup of:   ${ForceUsername}"
		$User = Get-ADUser -Filter { UserPrincipalName -eq $ForceUsername -or SamAccountName -eq $ForceUsername}
		if ($User) {
			Write-Host "INFO: AD User Found:   ${User}"
			$currentAltSecId = $(get-aduser $user -properties altSecurityIdentities | select altSecurityIdentities).altSecurityIdentities
			if ($currentAltSecId -eq $IssuerSerial) {
				$StrongMappingUsed = $true
				Write-Host "INFO: AD User already has accurate Strong Mapping:   ${currentAltSecId}"
			}
			else {
				Write-Host "INFO: AD User will have Strong Mapping info updated with:   ${IssuerSerial} "
			}
		}
	}
	else {
		# Try finding the user with Strong User Certificate Mapping
		$User = Get-ADUser -Filter { altSecurityIdentities -eq $IssuerSerial }
		if ($User) {
			$StrongMappingUsed = $true
			Write-Host "INFO: AD User Found:   ${User}"
			Write-Host "INFO: AD User already has accurate Strong Mapping:   $IssuerSerial"
		}
		else {
			# User couldn't be found with Strong Mapping.
			# Try locating the user with Weak Mapping (User Principal Name, located as the "Other Name" field of the "Subject Alternative Name" extension of the cert).
			# It's common to have this msUPN set to the "Logon Name" in AD.
			# Extracting it from the X509 cert takes some tricky and regex...
			# If we find the user, we'll add Strong Mapping support so this is no longer needed.
			$certSAN = -join $($Certificate | select @{name='Subject Alternative Name';expression={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Subject Alternative Name"}).format($false)}})
			$userPrincipalName = [regex]::Match($certSAN, 'Principal Name=(.*\@.*?)(?=\s*,|\s*\})').Groups[1].Value
			if ($userPrincipalName -ne "") {
				$User = Get-ADUser -Filter { UserPrincipalName -eq $userPrincipalName }
				if ($User) {
					$StrongMappingUsed = $false
					Write-Host "INFO: AD User Found with Weak Mapping:   ${User}"
					Write-Host "INFO: AD User will have Strong Mapping info updated with:   ${IssuerSerial} "
				}
			}
		}
	}
	return [PSCustomObject]@{
		User = $User
		StrongMappingUsed = $StrongMappingUsed
		IssuerSerial = $IssuerSerial
    }
}

###########################################################
# Step 5: Handle user not found
###########################################################

function 5_HandleMissingUser() {
	param ([Object]$User)
	# Despite all the above methods in Step 4, we couldn't find the user in AD. Exit.
	if (-not $User) {
		Write-Host "ERROR: User not found in Active Directory."
		exit
	}
}

###########################################################
# Step 6: Update altSecurityIdentities (if needed)
###########################################################

# If applicable (user was found with weak mapping, or they were found with the username override and their strong mapping field was incorrect), 
# set the altSecurityIdentities field that we calculated in Step 4.
function 6_UpdateStrongMapping() {
	param ([Object]$User, [bool]$StrongMappingUsed, [string]$IssuerSerial)
	if (-not $StrongMappingUsed -and -not $ReadOnly) {
		Write-Host "INFO: Setting Strong Mapping field (altSecurityIdentities) for user. Please confirm:"
		Set-ADUser -Identity $User -Confirm -Replace @{'altSecurityIdentities' = $IssuerSerial}
	}
}

###########################################################
# Step 7: Publish certificate for user
###########################################################

# Get the certificates of the User in AD. For each one that has "Client Authentication" EKU, check its thumbprint (hash).
# If the thumbprint matches the cert that was passed into this script, then there's no need to upload it.
# If published certs are found that support client auth but don't match the thumbprint, offer to remove them.
function 7_UpdateCert() {
	param ([Object]$Certificate, [Object]$User)
	$FoundCertificate = $false
	$PublishedCertificates = Get-ADUser -Identity $User -Properties Certificates  | 
		ForEach-Object { $_.Certificates | 
				foreach { New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $_ } | 
					Where-Object { $_.EnhancedKeyUsageList.FriendlyName -eq "Client Authentication" }
		} | ForEach-Object {
			# ...we have "certificate" objects here
			if ($_.Thumbprint -eq $Certificate.thumbprint) {
				$FoundCertificate = $true
				Write-Host "INFO: Correct user certificate already published (thumbprint matches)."
			}
			else {
				#Certificate found where the thumbprint doesn't match, so it should be removed
				$thumb = $_.Thumbprint
				if ($ReadOnly) {
					Write-Host "INFO: Mismatched user certificate found, but this execution is Read-Only. Thumbprint: ${thumb}"
				}
				#Implied else (i.e. write-mode)...
				Write-Host "INFO: Incorrect user certificate found (Thumbprint: ${thumb}). Remove it?"
				Set-ADUser -Identity $User -Confirm -Certificates @{Remove=$_}
			}
		}

	#If the certificate was not found to be already on the user's AD account, offer to upload it.
	if (-not $FoundCertificate -and -not $ReadOnly) {
		Write-Host "INFO: Setting new Published Certificate for user. Upload it?:"
		Set-ADUser -Identity $User -Confirm -Certificates @{Add=$Certificate}
	}
}

###########################################################
function main() {
	try { $Certificate = 1_LoadCert } catch { Write-Host "ERROR: in 1_LoadCert: $_"; exit 1 }
	try { 2_TestCert -C $Certificate } catch { Write-Host "ERROR: in 2_TestCert: $_"; exit 1 }
	try { 3_CheckEKU -C $Certificate } catch { Write-Host "ERROR: in 3_CheckEKU: $_"; exit 1 }
	try { $4meta = 4_FindUser -C $Certificate } catch { Write-Host "ERROR: in 4_FindUser: $_"; exit 1 }
		try { $User = $4meta.User
			$StrongMappingUsed = $4meta.StrongMappingUsed
			$IssuerSerial = $4meta.IssuerSerial } catch { Write-Host "ERROR: Issue reading results from 4_FindUser: $_"; exit 1 }
	try { 5_HandleMissingUser -U $User } catch { Write-Host "ERROR: in 5_HandleMissingUser: $_"; exit 1 }
	try { 6_UpdateStrongMapping -U $User -S $StrongMappingUsed -I $IssuerSerial } catch { Write-Host "ERROR: in 6_UpdateStrongMapping: $_"; exit 1 }
	try { 7_UpdateCert -C $Certificate -U $User } catch { Write-Host "ERROR: in 7_UpdateCert: $_"; exit 1 }
	
	#Now that Strong Mapping should now be supported for the user, and the user's Smart Card certificate should be published, all PKI logins over SSH should work on Domain-joined RHEL hosts.
	Write-Host "INFO: Done."
}
###########################################################
main
# :)