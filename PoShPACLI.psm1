###Helper Functions###

Function Test-ExePreReqs{

    <#
    .SYNOPSIS
        Test Pre-Requisites needed for PACLI exeutbale to run.
        
    .DESCRIPTION
        Module functions which call the PACLI utility require that a specific variable 
        is set to the full path of the PACLI utiltiy on the Local System and is in a scope 
        accesible to the function.
        Function Test-ExePreReqs ensures that both the variable is set, and that the path 
        to the utility stored int he variable resolves OK.
        
        Returns True or False (if one or both of the conditions is not met).
        
    .PARAMETER pacliVar
        The name of the variable containing the path to the PACLI Utility.

    .EXAMPLE
        Test-ExePreReqs
        
    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
        
    [CmdLetBinding()]
    param([Parameter(Mandatory=$False)][string]$pacliVar = "pacli")

    ((Get-Variable -Name $pacliVar -ErrorAction SilentlyContinue) -and 
        
        (Test-Path (Get-Variable -Name pacli -ValueOnly -ErrorAction SilentlyContinue) `
            -PathType leaf -Include "*.exe" -ErrorAction SilentlyContinue))
    
}

Function ConvertFrom-PacliOutput{

    <#
    .SYNOPSIS
    	Converts the quote enclosed, comma separated string returned by certain 
        PACLI commands to unquoted string values contained in an array.

    .DESCRIPTION
    	The PACLI executable returns raw string data from certain functions.
        Passing the output through this function allows the  values to be 
        extracted from the string and returned in an array for further processing.

    .PARAMETER pacliOutput
    	The string Returned from the PACLI executable.
        
        PACLI commands which return output should be called with the 'ENCLOSE'
        output option to ensure all values are enclised in quotation marks. 
        
        All whitespace should be removed from the PACLI output via a 
        Select-String -Pattern "\S" pattern match in order to prevent blank lines
        in the PACLI output affecting the number of property values returned by
        this function.

    .PARAMETER regEx
    	A Regular Expression String. This is applied to the quoted output from 
        the PACLI function to extract the quoted values from the string.
        
        The default Regular Expression used is: '"([^"]*)"'

    .EXAMPLE
        foreach ($pacliLine in $pacliOuPut){
    	
            $returnValues = $pacliLine | ConvertFrom-PacliOutput
        
        }
        
        Outputs an array containing the returned property values for each line
        of PACLI output passed to this function.
        
    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)][string]$pacliOutput,
        [Parameter(Mandatory=$False,ValueFromPipeline=$False)][string]$regEx = '"([^"]*)"'
    )

    Begin{
        
        #define array to hold values
        $pacliValues = @()

    }
    
    Process{

        #remove line break characters in pacli output data, 
        ($pacliOutput -replace "\r\n",""| 
            
            #find all values between quotes
            Select-String -Pattern $regEx -AllMatches).matches | 
            
                foreach{
                    
                    #assign returned values to array and remove quotes
                    $pacliValues += $_.Value -replace '"',''
                    write-debug "Parameter Value #$($pacliValues.count): $($_.Value)"
                    
                }

    }
    
    End{
        
        #return array of values
        $pacliValues
        
    }

}

Function ConvertTo-ParameterString{

    <#
    .SYNOPSIS
    	Converts bound parameters from called functions to a quoted string formatted
        to be supplied to the PACLI command line tool

    .DESCRIPTION
    	Allows values supplied against PowerShell function parameters to be easily
        translated into a specifically formatted string to be used to supply 
        arguments to native PACLI functions.
        
        Common Parameters, like Verbose or Debug, which may be contained in the array
        passed to this function are exluded from the output by default as they will 
        not be interpreted by the PACLI utility and will result in an error.

    .PARAMETER boundParameters
    	The bound parameter object from a PowerShell function.
        
    .PARAMETER quoteOutput
    	Specifies whether arguments and values contained in output string should be quoted

    .PARAMETER excludedParameters
        Array of parameters, of which the names and values should not be included in the 
        output string.
        
        By default this contains all PowerShell Common Parameter Names:
            Debug
            ErrorAction
            ErrorVariable
            OutVariable
            OutBuffer
            PipelineVariable
            Verbose
            WarningAction
            WarningVariable
            WhatIf
            Confirm
    
        Common Parameters may be contained in the array passed to this function, and must 
        be excluded from the output as they will not be interpreted by the PACLI utility 
        and will therefore result in an error.
        
    .EXAMPLE
    	$PSBoundParameters.getEnumerator() | ConvertTo-ParameterString
        
        Outputs a string where the Key/Value pairs contained in PSBoundParameters are converted into KEY=VALUE

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)][array]$boundParameters,
        [Parameter(Mandatory=$False,ValueFromPipeline=$False)][switch]$quoteOutput,
        [Parameter(Mandatory=$False,ValueFromPipeline=$False)][array]$excludedParameters = @(
            "Debug","ErrorAction","ErrorVariable","OutVariable","OutBuffer","PipelineVariable",
                "Verbose","WarningAction","WarningVariable","WhatIf","Confirm")
    )

    Begin{
    
        write-debug "Processing Bound Parameters"
        #define array to hold parameters
        $parameters=@()
        
    }
    
    Process{
        
        #foreach elemant in passed array
        $boundParameters | foreach{
        
            If($excludedParameters -notContains $_.key){
                    
                #add key=value to array, process switch values to equate TRUE=Yes, FALSE=No
                #$parameters+=$($_.Key)+"="+(($($_.Value) -replace "True", "YES") -replace "False", "NO")
                If (($_.Value -eq "True") -Or ($_.Value -eq "False")) {
                    $parameters+=$($_.Key)+"="+(($($_.Value) -replace "True", "YES") -replace "False", "NO")
                } else {
                    $parameters+=$($_.Key)+"=`""+(($($_.Value)+"`"" -replace "True", "YES") -replace "False", "NO")
                }
            }
                
        }    
        
    }
    
    End{
        
        if($parameters){

            $parameters = $parameters -join ' '
                        
            If($quoteOutput){
            
                #Add required quotes at whitespaces, at thh start and end of string and around '=' symbol
                $parameters = ((($parameters -replace "(\s)",'""" "') -replace "(^)|($)",'"') -replace "(=)",'=""')
            
            }

            $parameters+=";"    
            write-debug $parameters
            #output parameter string
            $parameters

        }
        
    }

}

###Module Setup Functions###

Function Initialize-PoShPACLI{

    <#
    .SYNOPSIS
    	Sets required variables needed to run Module/PACLI Functions.

    .DESCRIPTION
    	Finds, in the local environment PATH, or sets the path to the PACLI utility
        using a folder location provided as a parameter to the function.
        A variable called $pacli is set in the parent scope and is used by other functions in the module
        to locate the PACLI executable. 

    .PARAMETER pacliFolder
        If PACLI is does not reside in a folder in the local PATH Enviromental variable,
        supply the folder in which to find the PACLI executable against this parameter.
    
    .PARAMETER pacliExe
        Supply the name of the PACLI executable if it is different to "PACLI.EXE"
        
    .PARAMETER scope
        The scope in which to set the variables required for the module functions to run.
        By default this is set to "1" (the parent scope).
    
    .EXAMPLE
        Initialize-PoShPACLI
        
    .EXAMPLE
        Initialize-PoShPACLI -pacliFolder C:\Software\Pacli\
        
    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
        
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$False)][ValidateScript({Test-Path $_ -PathType container})][string]$pacliFolder,
        [Parameter(Mandatory=$False)][string]$pacliExe = "PACLI.EXE",
        [Parameter(Mandatory=$False)][ValidateSet("Global","Local","Script","Private",0,1,2,3)][string]$scope = 1
    )
    
    #Force remove pacli variable in specifed scope
    Remove-Variable -scope $scope -name pacli -Force -ErrorAction SilentlyContinue
    
    Try{
    
        #if no folder path has been supplied to function
        if($PSBoundParameters.keys -notcontains "pacliFolder"){
            
            #look for PACLI in the PATH environmental variable
            $pacliPath = (Get-Command -Name $pacliExe -CommandType Application -ErrorAction Stop | 

                Select -ExpandProperty Definition) | select -First 1

        }
        
        Else{
            
            If(!(Test-Path ($pacliPath = Join-Path -path $pacliFolder -childPath $pacliExe) -pathType Leaf -include $pacliExe -ErrorAction Stop)){

                #not valid/pacli.exe not found in folder
                throw
    
            }
        
        }
        
    }
    
    Catch{
    
        #pacli not found
        Remove-Variable -name pacliPath -ErrorAction SilentlyContinue
        Write-Error "PACLI Utility not found: Provide a valid folder location for the utility"
        
    }
    
    Finally{
    
        If(!(get-variable -name pacliPath -ErrorAction SilentlyContinue)){
        
            #pacli not found/path not set
            
        }
        
        Else{
        
            Set-Variable -Scope $scope -name pacli -Value $pacliPath -Force -PassThru -ErrorAction Stop

        }
    
    }
    
}

###Getting Started Functions###

Function Start-PACLI{

    <#
    .SYNOPSIS
    	Starts the PACLI executable. This command must be run before any other 
        commands.

    .DESCRIPTION
    	Exposes the PACLI Function: "INIT"

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .PARAMETER  ctlFileName
        The full path of the file that contains the Certificate Trust List (CTL).
    
    .EXAMPLE
    	Start-PACLI -sessionID $PID
        
        Starts the PACLI process with a session ID equal to the process ID of the current
        Powershell process.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
        
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$False)][int]$sessionID,
        [Parameter(Mandatory=$False)][string]$ctlFileName
    )
    
    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path

        Write-Verbose "Starting Pacli"
    
        $init = (Invoke-Expression "$pacli INIT $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)" -ErrorAction Stop) 2>&1
        
        if($LASTEXITCODE){
            
            Write-Debug $init
            Write-Debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "Error Starting Pacli"
            
            #Return FALSE

            
        }
        
        Else{
            
            Write-Debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "Pacli Started"
            
            #return TRUE

            
        }
        
    }

}

Function Stop-PACLI{

    <#
    .SYNOPSIS
    	This command terminates PACLI. Always run this at the end of every working
        session.

    .DESCRIPTION
    	Exposes the PACLI Function: "TERM"

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	Stop-PACLI
        Ends the PACLI process with a session ID of 0
        
    .EXAMPLE
    	Stop-PACLI -sessionID 7
        Ends the PACLI process with a session ID of 7

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path

        Write-Verbose "Stopping Pacli"
        
        $term = (Invoke-Expression "$pacli TERM $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)" -ErrorAction SilentlyContinue) 2>&1
        
        if($LASTEXITCODE){
        
            Write-Debug $term
            write-debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "Error Stopping Pacli"
            
            #Return FALSE

            
        }
        
        Else{
            
            write-debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "Pacli Stopped"
            
            #return TRUE

            
        }
        
    }

}

###Session Management Functions###

Function Add-VaultDefinition{

    <#
    .SYNOPSIS
    	Enables a Vault to be defined

    .DESCRIPTION
    	Exposes the PACLI Function: "DEFINE"

    .PARAMETER vault
        The name of the Vault to create.
        
    .PARAMETER address
        The IP address of the Vault.
        
    .PARAMETER port
        The Vault IP port.
        
    .PARAMETER timeout
        The number of seconds to wait for a Vault to respond to a
        command before a timeout message is displayed.

    .PARAMETER behindFirewall
        Whether or not the Vault will be accessed via a Firewall.
        
    .PARAMETER reconnectPeriod
        The number of seconds to wait before the sessions with the
        Vault is re-established.

    .PARAMETER useOnlyHTTP1
        Use only HTTP 1.0 protocol. This parameter is valid either
        with proxy settings or with ‘behindfirewall’.

    .PARAMETER proxyType
        The type of proxy through which the Vault is accessed. Valid
        values for this parameter are: HTTP, HTTPS, SOCKS4, SOCKS5, NOPROXY

    .PARAMETER proxyAddress
        The proxy server IP address. This is mandatory when using
        a proxy server.

    .PARAMETER proxyPort
        The Proxy server IP Port
        
    .PARAMETER proxyUser
        User for Proxy server if NTLM authentication is required
        
    .PARAMETER proxyPassword
        User's Password for Proxy server
        
    .PARAMETER proxyAuthDomain
        The authentication domain of the proxy
        
    .PARAMETER numOfRecordsPerSend
        The number of file records to transfer together in a single
        TCP/IP send/receive commands.

    .PARAMETER numOfRecordsPerChunk
        The number of file records to transfer together in a single
        TCP/IP send/receive operation.

    .PARAMETER enhancedSSL
        Whether or not an Enhanced SSL-based connection (port
        443) is required.

    .PARAMETER preAuthSecuredSession
        Whether or not pre-authentication secured session is enabled.

    .PARAMETER trustSSC
        Whether or not self-signed certificates are trusted for preauthentication
        secured sessions.
        Note: This parameter can only be enabled if 'preauthsecuredsession' is specified.

    .PARAMETER allowSSCFor3PartyAuth
        Whether or not to allow 3rd party authentication with selfsigned certificates.
        Note: This parameter can only be enabled if 'trustssc' is specified.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$address,
        [Parameter(Mandatory=$False)][int]$port,
        [Parameter(Mandatory=$False)][int]$timeout,
        [Parameter(Mandatory=$False)][switch]$behindFirewall,
        [Parameter(Mandatory=$False)][int]$reconnectPeriod,
        [Parameter(Mandatory=$False)][switch]$useOnlyHTTP1,
        [Parameter(Mandatory=$False)]
            [ValidateSet("HTTP","HTTPS","SOCKS4","SOCKS5","NOPROXY")]
            [string]$proxyType,
        [Parameter(Mandatory=$False)][string]$proxyAddress,
        [Parameter(Mandatory=$False)][int]$proxyPort,
        [Parameter(Mandatory=$False)][string]$proxyUser,
        [Parameter(Mandatory=$False)][string]$proxyPassword,
        [Parameter(Mandatory=$False)][string]$proxyAuthDomain,
        [Parameter(Mandatory=$False)][int]$numOfRecordsPerSend,
        [Parameter(Mandatory=$False)][int]$numOfRecordsPerChunk,
        [Parameter(Mandatory=$False)][switch]$enhancedSSL,
        [Parameter(Mandatory=$False)][switch]$preAuthSecuredSession,
        [Parameter(Mandatory=$False)][switch]$trustSSC,
        [Parameter(Mandatory=$False)][switch]$allowSSCFor3PartyAuth,
        [Parameter(Mandatory=$False)][int]$sessionID
    )
    
    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
            
        Write-Verbose "Defining Vault"
        
        $vaultDefinition = (Invoke-Expression "$pacli DEFINE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)" -ErrorAction SilentlyContinue) 2>&1
        
        if($LASTEXITCODE){

            write-debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose $($vaultDefinition)

            
        }
        
        Else{
            
            write-debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "Vault Defined"

            
        }    
        
    }

}

Function Read-VaultConfigFile{

    <#
    .SYNOPSIS
    	Defines a new Vault with parameters that reside in a text file.

    .DESCRIPTION
    	Exposes the PACLI Function: "DEFINEFROMFILE"

    .PARAMETER parmFile
        The full pathname of the file containing the parameters for
        defining the Vault.
        
    .PARAMETER vault
        The name of the Vault to create. This name can also be
        specified in the text file, although specifying it in this command
        overrides the Vault name in the file.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$parmFile,
        [Parameter(Mandatory=$False)][string]$vault,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                
        Write-Verbose "Defining Vault"
        
        $vaultConfig = (Invoke-Expression "$pacli DEFINEFROMFILE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)" -ErrorAction SilentlyContinue) 2>&1
        
        if($LASTEXITCODE){

            write-debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose $($vaultConfig)

            
        }
        
        Else{
            
            write-debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "Vault Config Read"

            
        }
        
    }

}

Function Remove-VaultDefinition{

    <#
    .SYNOPSIS
    	Deletes a Vault definition

    .DESCRIPTION
    	Exposes the PACLI Function: "DELETEVAULT"

    .PARAMETER vault
        The name of the Vault to delete.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$False)][string]$vault,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
            
        $removeVault = (Invoke-Expression "$pacli DELETEVAULT $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)" -ErrorAction SilentlyContinue) 2>&1
        
        if($LASTEXITCODE){

            write-debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
            
            write-debug "LastExitCode: $LASTEXITCODE"

            
        }  
        
    }  

}

Function Connect-Vault{

    <#
    .SYNOPSIS
    	This command enables you to log onto the Vault.

    .DESCRIPTION
        Exposes the PACLI Function: "LOGON"
    	Either log onto the Vault with this function by specifying a username and  
        password or by using an authentication parameter file. To create this file, 
        see the New-LogonFile command.

    .PARAMETER vault
        The name of the Vault to log onto
        
    .PARAMETER user
        The Username of the User logging on
        
    .PARAMETER password
        The User’s password.
        Note: The LOGONFILE and PASSWORD parameters cannot be defined together.

    .PARAMETER newPassword
        The User’s new password (if the User would like to change password at 
        logon time) or NULL.
        Note: The LOGONFILE and NEWPASSWORD parameters cannot be defined together.

    .PARAMETER logonFile
        The full pathname of the logon parameter file which contains the User’s 
        name and scrambled password.
        Note: The logonfile parameter cannot be defined with the RADIUS, PASSWORD, 
        or NEWPASSWORD parameters.

    .PARAMETER autoChangePassword
        Determines whether or not the password is automatically changed each time 
        the User logs onto the Vault. 
        It is only relevant when you use the LogonFile parameter of the 
        CreateLogonFile command. 
        It will generate a randomized new password, change to the new password on 
        logon, and will save it to the  authentication file after a successful logon.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .PARAMETER failIfConnected
        Whether or not to disconnect the session if the user is already logged onto 
        the Vault through a different interface

    .PARAMETER radius
        Whether or not to enable Radius authentication to the Vault.
        Notes:
            PACLI does not support challenge response for RADIUS authentication.
            The logonfile and radius parameters cannot be defined in the same command.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
        
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$False)][string]$password,
        [Parameter(Mandatory=$False)][string]$newPassword,
        [Parameter(Mandatory=$False)][string]$logonFile,
        [Parameter(Mandatory=$False)][switch]$autoChangePassword,
        [Parameter(Mandatory=$False)][int]$sessionID,
        [Parameter(Mandatory=$False)][switch]$failIfConnected,
        [Parameter(Mandatory=$False)][switch]$radius
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
            
        Write-Verbose "Logging onto Vault"
        
        $pacliLogon = (Invoke-Expression "$pacli LOGON $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)" -ErrorAction SilentlyContinue) 2>&1

        if($LASTEXITCODE){
            
            write-debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "Error Logging on"
            Write-Debug $($pacliLogon|out-string)

            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "Succesfully Logged on"

            
        }
        
    }

}

Function New-LogonFile{

    <#
    .SYNOPSIS
    	This command creates a logon file that contains the information required 
        for a User to log onto the Vault. After this file has been created, it 
        can be used with the Connect-Vault command.

    .DESCRIPTION
    	Exposes the PACLI Function: "CREATELOGONFILE"

    .PARAMETER logonFile
        The full pathname of the file that contains all the User information to
        enable logon to the Vault

    .PARAMETER username
        The username of the user carrying out the task on the external token
        
    .PARAMETER password
        The password to save in the logon file that will allow logon to the Vault.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
        
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$logonFile,
        [Parameter(Mandatory=$False)][string]$username,
        [Parameter(Mandatory=$False)][string]$password,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
            
        $newLogonFile = (Invoke-Expression "$pacli CREATELOGONFILE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)" -ErrorAction SilentlyContinue) 2>&1

        if($LASTEXITCODE){
            
            write-debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Disconnect-Vault{

    <#
    .SYNOPSIS
    	This command enables log off from the Vault

    .DESCRIPTION
    	Exposes the PACLI Function: "LOGOFF"
    
    .PARAMETER vault
        The name of the Vault to log off from.
        
    .PARAMETER user
        The name of the User who is logging off.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)]$vault,
        [Parameter(Mandatory=$True)]$user,
        [Parameter(Mandatory=$False)]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path

        Write-Verbose "Logging off from Vault"
        
        $pacliLogoff = (Invoke-Expression "$pacli LOGOFF $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1

        if($LASTEXITCODE){
            
            Write-Debug "LastExitCode: $LASTEXITCODE"
            Write-Debug $pacliLogoff

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

###User Management Functions###

Function Set-Password{

    <#
    .SYNOPSIS
    	Enables you to change your CyberArk User password.

    .DESCRIPTION
    	Exposes the PACLI Function: "SETPASSWORD"

    .PARAMETER vault
        The name of the Vault to which the User has access
        
    .PARAMETER user
        The Username of the User who is logged on
        
    .PARAMETER password
        The User’s current password.
        
    .PARAMETER newPassword
        The User’s new password.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$password,
        [Parameter(Mandatory=$True)][string]$newPassword,
        [Parameter(Mandatory=$False)][int]$sessionID
    )
    
    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
    
        $deleteRequest = Invoke-Expression "$pacli SETPASSWORD $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Lock-User{

    <#
    .SYNOPSIS
    	Locks the current User’s CyberArk account.

    .DESCRIPTION
    	Exposes the PACLI Function: "LOCK"
        
    .PARAMETER vault
        The name of the Vault to which the User is logged on.
        
    .PARAMETER user
        The Username of the User who is logged on
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$False)][int]$sessionID
    )
    
    If(!(Test-ExePreReqs)){
            
            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path        
        $lockUser = Invoke-Expression "$pacli LOCK $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Unlock-User{

    <#
    .SYNOPSIS
    	Unlocks the User account of the CyberArk User who is currently logged on.

    .DESCRIPTION
    	Exposes the PACLI Function: "UNLOCK"
    
    .PARAMETER vault
        The name of the Vault to which the User is logged on.
        
    .PARAMETER user
        The Username of the User whose account is locked

    .PARAMETER password
        The User’s password
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$False)][string]$password,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
            
        $unlockUser = Invoke-Expression "$pacli UNLOCK $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Add-User{

    <#
    .SYNOPSIS
    	Enables a CyberArk User to be added to the Vault, and given administration 
        permissions.

    .DESCRIPTION
    	Exposes the PACLI Function: "ADDUSER"

    .PARAMETER vault
        The name of the Vault to which the User will be added.
        
    .PARAMETER user
        The Username of the User who is logged on
        
    .PARAMETER destUser
        The name of the User to add to the Vault.
        
    .PARAMETER authType

        The type of authentication by which the User will logon to the Vault. 
        Specify one of the following:
        PA_AUTH – Password authentication. This is the default.
        NT_AUTH – NT authentication.
        NT_OR_PA_AUTH – Either password or NT authentication.
        PKI_AUTH – PKI authentication. This requires a valid certfilename parameter.
        RADIUS_AUTH – Radius authentication. This does not require any other 
            additional parameters.
        LDAP_AUTH – LDAP authentication.
        
    .PARAMETER requireSecureIDAuth
        Whether or not the User is required to provide a SecurID passcode as well 
        as the method specified in the authtype parameter

    .PARAMETER password
        The password of the User to add to the Vault, if the authentication type 
        is PA_AUTH.
        
    .PARAMETER certFileName
        The name of the certificate file that enables users to log on with PKI 
        authentication.
        
        Use either this parameter or ‘dn’.
        If Vault version is lower than version 3.5, this parameter must be specified.
        
    .PARAMETER DN
        The User's Distinguished Name received from the directory or Certified Authority. 
        This parameter enables users to log on with PKI authentication.
        Use either this parameter or ‘CertFileName’.

    .PARAMETER location
        The location from which the User will log on.
        A backslash ‘\’ must be added before the name of the location.
        
    .PARAMETER usersAdmin
        Whether or not the User can manage other Users
        
    .PARAMETER resetPassword
        Whether or not the User can reset user’s passwords or select ‘User Must Change 
        Password at Next Logon’ for other users.

    .PARAMETER activateUsers
        Whether or not the User can activate or deactivate user network areas.

    .PARAMETER safesAdmin
        Whether or not the User can manage Safes.
        
    .PARAMETER networksAdmin
        Whether or not the User can manage network settings
        
    .PARAMETER rulesAdmin
        Whether or not the User can manage external user rules.
        
    .PARAMETER categoriesAdmin
        Whether or not the User can edit File Categories
        
    .PARAMETER auditAdmin
        Indicates whether or not the User can audit users in the same location or sublocations 
        in the Vault hierarchy.

    .PARAMETER backupAdmin
        Whether or not the User can backup all the Safes in the Vault.
        
    .PARAMETER restoreAdmin
        Whether or not the User can restore all the Safes in the Vault.
        
    .PARAMETER gatewayAccount
        Whether or not this account is a Gateway account.
        Note: A Gateway account user can only authenticate to the Vault with either password 
        or RADIUS authentication.

    .PARAMETER retention
        The number of days to keep the User log records.
        
    .PARAMETER firstName
        The User’s first name.
        
    .PARAMETER middleName
        The User’s middle name.
        
    .PARAMETER lastName
        The User’s last name.
        
    .PARAMETER quota
        The disk quota that is allocated to the location in MB.
        The specification ‘-1’ indicates an unlimited quota allocation.

    .PARAMETER disabled
        Whether or not the User account is disabled.
        
    .PARAMETER passwordNeverExpires
        Whether or not the User’s password never expires.
        
    .PARAMETER ChangePassword
        Whether or not the User is required to change their password 
        after they logon for the first time.

    .PARAMETER expirationDate
        The date on which the User’s account expires, if applicable.
        
    .PARAMETER homeStreet
        The name of the street where the User lives.
        
    .PARAMETER homeCity
        The name of the city where the User lives.
        
    .PARAMETER homeState
        The name of the state where the User lives
        
    .PARAMETER homeCountry
        The name of the country where the User lives.
        
    .PARAMETER homeZIP
        The zip code of the User’s address.
        
    .PARAMETER workPhone
        The User’s work phone number.
        
    .PARAMETER homePhone
        The User’s home phone number.
        
    .PARAMETER cellular
        The User’s cellular phone number.
        
    .PARAMETER fax
        The User’s fax number.
        
    .PARAMETER pager
        The number of the User’s pager
        
    .PARAMETER hEmail
        The User’s home e-mail address
        
    .PARAMETER bEmail
        The User’s business e-mail address.
        
    .PARAMETER oEmail
        Another e-mail address for the User.
        
    .PARAMETER jobTitle
        The User’s job title.
        
    .PARAMETER organization
        The name of the User’s organization.
        
    .PARAMETER department
        The name of the User’s department.
        
    .PARAMETER profession
        The User’s profession.
        
    .PARAMETER workStreet
        The street where the User’s office is located.
        
    .PARAMETER workCity
        The city where the User’s office is located.
        
    .PARAMETER workState
        The state where the User’s office is located.
        
    .PARAMETER workCountry
        The country where the User’s office is located.
        
    .PARAMETER workZip
        The zip code of the User’s office address.
        
    .PARAMETER homePage
        The URL of the homepage of the User’s company.
        
    .PARAMETER notes
        Optional notes about the User.
        
    .PARAMETER userTypeName
        The name of the user type allocated to this user.
        
    .PARAMETER authorizedInterfaces
        The CyberArk interfaces that this user is authorized to use.
        
    .PARAMETER enableComponentMonitoring
        Whether or not email notifications are sent for component users who 
        have not accessed the Vault.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$destUser,
        [Parameter(Mandatory=$False)][string]$authType,
        [Parameter(Mandatory=$False)][switch]$requireSecureIDAuth,
        [Parameter(Mandatory=$False)][string]$password,
        [Parameter(Mandatory=$False)][string]$certFileName,
        [Parameter(Mandatory=$False)][string]$DN,
        [Parameter(Mandatory=$False)][string]$location,
        [Parameter(Mandatory=$False)][switch]$usersAdmin,
        [Parameter(Mandatory=$False)][switch]$resetPassword,
        [Parameter(Mandatory=$False)][switch]$activateUsers,
        [Parameter(Mandatory=$False)][switch]$safesAdmin,
        [Parameter(Mandatory=$False)][switch]$networksAdmin,
        [Parameter(Mandatory=$False)][switch]$rulesAdmin,
        [Parameter(Mandatory=$False)][switch]$categoriesAdmin,
        [Parameter(Mandatory=$False)][switch]$auditAdmin,
        [Parameter(Mandatory=$False)][switch]$backupAdmin,
        [Parameter(Mandatory=$False)][switch]$restoreAdmin,
        [Parameter(Mandatory=$False)][switch]$gatewayAccount,
        [Parameter(Mandatory=$False)][int]$retention,
        [Parameter(Mandatory=$False)][string]$firstName,
        [Parameter(Mandatory=$False)][string]$middleName,
        [Parameter(Mandatory=$False)][string]$lastName,
        [Parameter(Mandatory=$False)][int]$quota,
        [Parameter(Mandatory=$False)][switch]$disabled,
        [Parameter(Mandatory=$False)][switch]$passwordNeverExpires,
        [Parameter(Mandatory=$False)][switch]$ChangePassword,
        [Parameter(Mandatory=$False)][string]$expirationDate,
        [Parameter(Mandatory=$False)][string]$homeStreet,
        [Parameter(Mandatory=$False)][string]$homeCity,
        [Parameter(Mandatory=$False)][string]$homeState,
        [Parameter(Mandatory=$False)][string]$homeCountry,
        [Parameter(Mandatory=$False)][string]$homeZIP,
        [Parameter(Mandatory=$False)][string]$workPhone,
        [Parameter(Mandatory=$False)][string]$homePhone,
        [Parameter(Mandatory=$False)][string]$cellular,
        [Parameter(Mandatory=$False)][string]$fax,
        [Parameter(Mandatory=$False)][string]$pager,
        [Parameter(Mandatory=$False)][string]$hEmail,
        [Parameter(Mandatory=$False)][string]$bEmail,
        [Parameter(Mandatory=$False)][string]$oEmail,
        [Parameter(Mandatory=$False)][string]$jobTitle,
        [Parameter(Mandatory=$False)][string]$organization,
        [Parameter(Mandatory=$False)][string]$department,
        [Parameter(Mandatory=$False)][string]$profession,
        [Parameter(Mandatory=$False)][string]$workStreet,
        [Parameter(Mandatory=$False)][string]$workCity,
        [Parameter(Mandatory=$False)][string]$workState,
        [Parameter(Mandatory=$False)][string]$workCountry,
        [Parameter(Mandatory=$False)][string]$workZip,
        [Parameter(Mandatory=$False)][string]$homePage,
        [Parameter(Mandatory=$False)][string]$notes,
        [Parameter(Mandatory=$False)][string]$userTypeName,
        [Parameter(Mandatory=$False)][string]$authorizedInterfaces,
        [Parameter(Mandatory=$False)][switch]$enableComponentMonitoring,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
            
        $addUser = Invoke-Expression "$pacli ADDUSER $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Update-User{

    <#
    .SYNOPSIS
    	Enables a CyberArk User with the appropriate authority to update the 
        properties of a CyberArk User account.

    .DESCRIPTION
    	Exposes the PACLI Function: "UPDATEUSER"

    .PARAMETER vault
        The name of the Vault.
        
    .PARAMETER user
        The Username of the User who is logged on.
        
    .PARAMETER destUser
        The name of the User to be updated.
        
    .PARAMETER authType

        The type of authentication by which the User will logon to the Vault. 
        Specify one of the following:
            PA_AUTH – Password authentication. This is the default.
            NT_AUTH – NT authentication.
            NT_OR_PA_AUTH – Either password or NT authentication.
            PKI_AUTH – PKI authentication. This requires a valid certfilename parameter.
            RADIUS_AUTH – Radius authentication. This does not require any other 
                additional parameters.
            LDAP_AUTH – LDAP authentication.
        
    .PARAMETER requireSecureIDAuth
        Whether or not the User is required to provide a SecurID passcode as well 
        as the method specified in the authtype parameter

    .PARAMETER password
        The password of the User to add to the Vault, if the authentication type 
        is PA_AUTH.
        
    .PARAMETER certFileName
        The name of the certificate file that enables users to log on with PKI 
        authentication.
        
        Use either this parameter or ‘dn’.
        If Vault version is lower than version 3.5, this parameter must be specified.
        
    .PARAMETER DN
        The User's Distinguished Name received from the directory or Certified Authority. 
        This parameter enables users to log on with PKI authentication.
        Use either this parameter or ‘CertFileName’.

    .PARAMETER location
        The location from which the User will log on.
        A backslash ‘\’ must be added before the name of the location.
        
    .PARAMETER usersAdmin
        Whether or not the User can manage other Users
        
    .PARAMETER resetPassword
        Whether or not the User can reset user’s passwords or select ‘User Must Change 
        Password at Next Logon’ for other users.

    .PARAMETER activateUsers
        Whether or not the User can activate or deactivate user network areas.

    .PARAMETER safesAdmin
        Whether or not the User can manage Safes.
        
    .PARAMETER networksAdmin
        Whether or not the User can manage network settings
        
    .PARAMETER rulesAdmin
        Whether or not the User can manage external user rules.
        
    .PARAMETER categoriesAdmin
        Whether or not the User can edit File Categories
        
    .PARAMETER auditAdmin
        Indicates whether or not the User can audit users in the same location or sublocations 
        in the Vault hierarchy.

    .PARAMETER backupAdmin
        Whether or not the User can backup all the Safes in the Vault.
        
    .PARAMETER restoreAdmin
        Whether or not the User can restore all the Safes in the Vault.
        
    .PARAMETER gatewayAccount
        Whether or not this account is a Gateway account.
        Note: A Gateway account user can only authenticate to the Vault with either password 
        or RADIUS authentication.

    .PARAMETER retention
        The number of days to keep the User log records.
        
    .PARAMETER firstName
        The User’s first name.
        
    .PARAMETER middleName
        The User’s middle name.
        
    .PARAMETER lastName
        The User’s last name.
        
    .PARAMETER quota
        The disk quota that is allocated to the location in MB.
        The specification ‘-1’ indicates an unlimited quota allocation.

    .PARAMETER disabled
        Whether or not the User account is disabled.
        
    .PARAMETER passwordNeverExpires
        Whether or not the User’s password never expires.
        
    .PARAMETER ChangePassword
        Whether or not the User is required to change their password 
        after they logon for the first time.

    .PARAMETER expirationDate
        The date on which the User’s account expires, if applicable.
        
    .PARAMETER homeStreet
        The name of the street where the User lives.
        
    .PARAMETER homeCity
        The name of the city where the User lives.
        
    .PARAMETER homeState
        The name of the state where the User lives
        
    .PARAMETER homeCountry
        The name of the country where the User lives.
        
    .PARAMETER homeZIP
        The zip code of the User’s address.
        
    .PARAMETER workPhone
        The User’s work phone number.
        
    .PARAMETER homePhone
        The User’s home phone number.
        
    .PARAMETER cellular
        The User’s cellular phone number.
        
    .PARAMETER fax
        The User’s fax number.
        
    .PARAMETER pager
        The number of the User’s pager
        
    .PARAMETER hEmail
        The User’s home e-mail address
        
    .PARAMETER bEmail
        The User’s business e-mail address.
        
    .PARAMETER oEmail
        Another e-mail address for the User.
        
    .PARAMETER jobTitle
        The User’s job title.
        
    .PARAMETER organization
        The name of the User’s organization.
        
    .PARAMETER department
        The name of the User’s department.
        
    .PARAMETER profession
        The User’s profession.
        
    .PARAMETER workStreet
        The street where the User’s office is located.
        
    .PARAMETER workCity
        The city where the User’s office is located.
        
    .PARAMETER workState
        The state where the User’s office is located.
        
    .PARAMETER workCountry
        The country where the User’s office is located.
        
    .PARAMETER workZip
        The zip code of the User’s office address.
        
    .PARAMETER homePage
        The URL of the homepage of the User’s company.
        
    .PARAMETER notes
        Optional notes about the User.
        
    .PARAMETER userTypeName
        The name of the user type allocated to this user.
        
    .PARAMETER authorizedInterfaces
        The CyberArk interfaces that this user is authorized to use.
        
    .PARAMETER enableComponentMonitoring
        Whether or not email notifications are sent for component users who 
        have not accessed the Vault.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$destUser,
        [Parameter(Mandatory=$False)][string]$authType,
        [Parameter(Mandatory=$False)][switch]$requireSecureIDAuth,
        [Parameter(Mandatory=$False)][string]$password,
        [Parameter(Mandatory=$False)][string]$certFileName,
        [Parameter(Mandatory=$False)][string]$DN,
        [Parameter(Mandatory=$False)][string]$location,
        [Parameter(Mandatory=$False)][switch]$usersAdmin,
        [Parameter(Mandatory=$False)][switch]$resetPassword,
        [Parameter(Mandatory=$False)][switch]$activateUsers,
        [Parameter(Mandatory=$False)][switch]$safesAdmin,
        [Parameter(Mandatory=$False)][switch]$networksAdmin,
        [Parameter(Mandatory=$False)][switch]$rulesAdmin,
        [Parameter(Mandatory=$False)][switch]$categoriesAdmin,
        [Parameter(Mandatory=$False)][switch]$auditAdmin,
        [Parameter(Mandatory=$False)][switch]$backupAdmin,
        [Parameter(Mandatory=$False)][switch]$restoreAdmin,
        [Parameter(Mandatory=$False)][int]$retention,
        [Parameter(Mandatory=$False)][string]$firstName,
        [Parameter(Mandatory=$False)][string]$middleName,
        [Parameter(Mandatory=$False)][string]$lastName,
        [Parameter(Mandatory=$False)][int]$quota,
        [Parameter(Mandatory=$False)][switch]$disabled,
        [Parameter(Mandatory=$False)][switch]$passwordNeverExpires,
        [Parameter(Mandatory=$False)][switch]$ChangePassword,
        [Parameter(Mandatory=$False)][string]$expirationDate,
        [Parameter(Mandatory=$False)][string]$homeStreet,
        [Parameter(Mandatory=$False)][string]$homeCity,
        [Parameter(Mandatory=$False)][string]$homeState,
        [Parameter(Mandatory=$False)][string]$homeCountry,
        [Parameter(Mandatory=$False)][string]$homeZIP,
        [Parameter(Mandatory=$False)][string]$workPhone,
        [Parameter(Mandatory=$False)][string]$homePhone,
        [Parameter(Mandatory=$False)][string]$cellular,
        [Parameter(Mandatory=$False)][string]$fax,
        [Parameter(Mandatory=$False)][string]$pager,
        [Parameter(Mandatory=$False)][string]$hEmail,
        [Parameter(Mandatory=$False)][string]$bEmail,
        [Parameter(Mandatory=$False)][string]$oEmail,
        [Parameter(Mandatory=$False)][string]$jobTitle,
        [Parameter(Mandatory=$False)][string]$organization,
        [Parameter(Mandatory=$False)][string]$department,
        [Parameter(Mandatory=$False)][string]$profession,
        [Parameter(Mandatory=$False)][string]$workStreet,
        [Parameter(Mandatory=$False)][string]$workCity,
        [Parameter(Mandatory=$False)][string]$workState,
        [Parameter(Mandatory=$False)][string]$workCountry,
        [Parameter(Mandatory=$False)][string]$workZip,
        [Parameter(Mandatory=$False)][string]$homePage,
        [Parameter(Mandatory=$False)][string]$notes,
        [Parameter(Mandatory=$False)][string]$userTypeName,
        [Parameter(Mandatory=$False)][string]$authorizedInterfaces,
        [Parameter(Mandatory=$False)][switch]$enableComponentMonitoring,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
            
        $updateUser = Invoke-Expression "$pacli UPDATEUSER $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Rename-User{

    <#
    .SYNOPSIS
    	Renames a CyberArk User

    .DESCRIPTION
    	Exposes the PACLI Function: "RENAMEUSER"

    .PARAMETER vault
        The name of the Vault.

    .PARAMETER user
        The Username of the User who is logged on.

    .PARAMETER destUser
        The current name of the User to rename.

    .PARAMETER newName
        The new name of the User.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$destUser,
        [Parameter(Mandatory=$True)][string]$newName,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
        
        $renameUser = Invoke-Expression "$pacli RENAMEUSER $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Remove-User{

    <#
    .SYNOPSIS
    	Enables a User with the appropriate authority to delete a CyberArk User.

    .DESCRIPTION
    	Exposes the PACLI Function: "DELETEUSER"

    .PARAMETER vault
    	The name of the Vault.

    .PARAMETER user
        The Username of the User who is logged on.

    .PARAMETER destUser
    	The name of the User to be deleted.
                        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$destUser,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
            
        $removeUser = Invoke-Expression "$pacli DELETEUSER $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Add-ExternalUser{

    <#
    .SYNOPSIS
    	Adds a new user from an external directory

    .DESCRIPTION
    	Exposes the PACLI Function: "ADDUPDATEEXTERNALUSERENTITY"

    .PARAMETER sessionID
    	

    .PARAMETER vault
    	The name of the Vault where the file is stored.

    .PARAMETER user
    	The Username of the User who is carrying out the task.

    .PARAMETER destUser
    	The name (samaccountname) of the external User or Group that will be created 
        in the Vault.

    .PARAMETER ldapFullDN
    	The full DN of the user in the external directory.

    .PARAMETER ldapDirectory
    	The name (netbios domain name) of the external directory where the user or 
        group is defined.

    .PARAMETER UpdateIfExists
    	Whether or not existing external Users and Groups definitions will be updated 
        in the Vault.
                    
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
        Work required to support LDAPFullDN & Parameter Validation / Parameter Sets
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)]
        [string]$vault,
        [Parameter(Mandatory=$True)]
        [string]$user,
        [Parameter(Mandatory=$True)]
        [string]$destUser,
        [Parameter(Mandatory=$False)]
        [string]$ldapFullDN,
        [Parameter(Mandatory=$True)]
        [string]$ldapDirectory,
        [Parameter(Mandatory=$False)]
        [switch]$UpdateIfExists,
        [Parameter(Mandatory=$False)]
        [int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
        
        [array]$addUser = (Invoke-Expression "$pacli ADDUPDATEEXTERNALUSERENTITY $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) Output '(ALL,ENCLOSE)'" -ErrorAction SilentlyContinue) 2>&1
        
        if($LASTEXITCODE){
            
            write-debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "Error Adding External User: $destUser"
            write-debug $($addUser[0]|Out-String)   
            
        }
        
        Else{
            
            write-debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "External User $destUser added."
            $addUser | ConvertFrom-PacliOutput
            
        }
        
    }
    
}

Function Get-UserDetails{

    <#
    .SYNOPSIS
    	Returns details about a specific CyberArk User.

    .DESCRIPTION
    	Exposes the PACLI Function: "USERDETAILS"
    
    .PARAMETER vault
	   The name of the Vault

    .PARAMETER user
	   The Username of the User who is logged on.

    .PARAMETER destUser
	   The name of the User whose details will be listed.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$destUser,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
            
        #execute pacli with parameters
        $userDetails = (Invoke-Expression "$pacli USERDETAILS $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'") | 
            
            #ignore whitespace lines
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"

            #if result(s) returned
            if($userDetails){
                
                #process each result
                foreach($user in $userDetails){
                    
                    #define hash to hold values
                    $vaultUser = @{}
                    
                    #split the command output
                    $values = $user | ConvertFrom-PacliOutput
                        
                    #assign values to properties
                    $vaultUser.Add("Name",$values[0])
                    $vaultUser.Add("Retention",$values[1])
                    $vaultUser.Add("UsersAdmin",$values[2])
                    $vaultUser.Add("SafesAdmin",$values[3])
                    $vaultUser.Add("NetworksAdmin",$values[4])
                    $vaultUser.Add("RulesAdmin",$values[5])
                    $vaultUser.Add("FileCategoriesAdmin",$values[6])
                    $vaultUser.Add("AuditAdmin",$values[7])
                    $vaultUser.Add("BackupAdmin",$values[8])
                    $vaultUser.Add("RestoreAdmin",$values[9])
                    $vaultUser.Add("Location",$values[10])
                    $vaultUser.Add("KeyFileName",$values[11])
                    $vaultUser.Add("FromHour",$values[12])
                    $vaultUser.Add("ToHour",$values[13])
                    $vaultUser.Add("FirstName",$values[14])
                    $vaultUser.Add("MiddleName",$values[15])
                    $vaultUser.Add("LastName",$values[16])
                    $vaultUser.Add("HomeStreet",$values[17])
                    $vaultUser.Add("HomeCity",$values[18])
                    $vaultUser.Add("HomeState",$values[19])
                    $vaultUser.Add("HomeCountry",$values[20])
                    $vaultUser.Add("HomeZIP",$values[21])
                    $vaultUser.Add("WorkPhone",$values[22])
                    $vaultUser.Add("HomePhone",$values[23])
                    $vaultUser.Add("Cellular",$values[24])
                    $vaultUser.Add("Fax",$values[25])
                    $vaultUser.Add("Pager",$values[26])
                    $vaultUser.Add("HEmail",$values[27])
                    $vaultUser.Add("BEmail",$values[28])
                    $vaultUser.Add("OEmail",$values[29])
                    $vaultUser.Add("JobTitle",$values[30])
                    $vaultUser.Add("Organization",$values[31])
                    $vaultUser.Add("Department",$values[32])
                    $vaultUser.Add("Profession",$values[33])
                    $vaultUser.Add("WorkStreet",$values[34])
                    $vaultUser.Add("WorkCity",$values[35])
                    $vaultUser.Add("WorkState",$values[36])
                    $vaultUser.Add("WorkCountry",$values[37])
                    $vaultUser.Add("WorkZip",$values[38])
                    $vaultUser.Add("HomePage",$values[39])
                    $vaultUser.Add("Notes",$values[40])
                    $vaultUser.Add("ExpirationDate",$values[41])
                    $vaultUser.Add("PassAuth",$values[42])
                    $vaultUser.Add("PKIAuth",$values[43])
                    $vaultUser.Add("SecureIDAuth",$values[44])
                    $vaultUser.Add("NTAuth",$values[45])
                    $vaultUser.Add("RadiusAuth",$values[46])
                    $vaultUser.Add("ChangePassword",$values[47])
                    $vaultUser.Add("PasswordNeverExpires",$values[48])
                    $vaultUser.Add("LDAPUser",$values[49])
                    $vaultUser.Add("Template",$values[50])
                    $vaultUser.Add("GWAccount",$values[51])
                    $vaultUser.Add("Disabled",$values[52])
                    $vaultUser.Add("Quota",$values[53])
                    $vaultUser.Add("UsedQuota",$values[54])
                    $vaultUser.Add("DN",$values[55])
                    $vaultUser.Add("Fingerprint",$values[56])
                    $vaultUser.Add("LDAPFullDN",$values[57])
                    $vaultUser.Add("LDAPDirectory",$values[58])
                    $vaultUser.Add("MapID",$values[59])
                    $vaultUser.Add("MapName",$values[60])
                    $vaultUser.Add("UserAuth",$values[61])
                    $vaultUser.Add("UserTypeID",$values[62])
                    $vaultUser.Add("NonAllowedClients",$values[63])
                    $vaultUser.Add("EnableComponentMonitoring",$values[64])
                    
                    #output object
                    new-object -Type psobject -Property $vaultUser | select Name, Retention, UsersAdmin, 
                        SafesAdmin, NetworksAdmin, RulesAdmin, FileCategoriesAdmin, AuditAdmin, BackupAdmin, RestoreAdmin, 
                            Location, KeyFileName, FromHour, ToHour, FirstName, MiddleName, LastName, HomeStreet, HomeCity, 
                                HomeState, HomeCountry, HomeZIP, WorkPhone, HomePhone, Cellular, Fax, Pager, HEmail, BEmail,
                                    OEmail, JobTitle, Organization, Department, Profession, WorkStreet, WorkCity, WorkState, 
                                        WorkCountry, WorkZip, HomePage, Notes, ExpirationDate, PassAuth, PKIAuth, SecureIDAuth, 
                                            NTAuth, RadiusAuth, ChangePassword, PasswordNeverExpires, LDAPUser, Template, GWAccount, 
                                                Disabled, Quota, UsedQuota, DN, Fingerprint, LDAPFullDN, LDAPDirectory, MapID, MapName, 
                                                    UserAuth, UserTypeID, NonAllowedClients, EnableComponentMonitoring
                
                }
            
            }
            
        }
        
    }
    
}

Function Get-VaultUsers{

    <#
    .SYNOPSIS
    	Produces a list of Users who have access to the specified Vault.
        You can only generate this list if you have administrative permissions.

    .DESCRIPTION
    	Exposes the PACLI Function: "USERSLIST"

    .PARAMETER vault
	   The name of the Vault

    .PARAMETER user
	   The Username of the User who is logged on.

    .PARAMETER location
	   The location to search for users.
	   Note: A backslash ‘\’ must be added before the name of the location.

    .PARAMETER includeSubLocations
	   Whether or not the output will include the sublocation in which the User 
       is defined.

    .PARAMETER includeDisabledUsers
	   Whether or not the output will include disabled users

    .PARAMETER onlyKnownUsers
	   Whether or not the output will include only Users who share Safes with 
       the User carrying out the command or all Users known by the specified Vault

    .PARAMETER userPattern
	   The full name or part of the name of the User(s) to include in the report. 
       A wildcard can also be used in this parameter.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$False)][string]$vault,
        [Parameter(Mandatory=$False)][string]$user,
        [Parameter(Mandatory=$False)][string]$location = "\",
        [Parameter(Mandatory=$False)][switch]$includeSubLocations,
        [Parameter(Mandatory=$False)][switch]$includeDisabledUsers,
        [Parameter(Mandatory=$False)][switch]$onlyKnownUsers,
        [Parameter(Mandatory=$False)][string]$userPattern,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
            
        #execute pacli with parameters
        $usersList = (Invoke-Expression "$pacli USERSLIST $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'") | 
            
            #ignore whitespace lines
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"

            #if result(s) returned
            if($usersList){
                
                #process each result
                foreach($user in $usersList){
                    
                    #define hash to hold values
                    $vaultUser = @{}
                    
                    #split the command output
                    $values = $user | ConvertFrom-PacliOutput
                        
                    #assign values to properties
                    $vaultUser.Add("Name",$values[0])
                    $vaultUser.Add("Quota",$values[1])
                    $vaultUser.Add("UsedQuota",$values[2])
                    $vaultUser.Add("Location",$values[3])
                    $vaultUser.Add("FirstName",$values[4])
                    $vaultUser.Add("LastName",$values[5])
                    $vaultUser.Add("LDAPUser",$values[6])
                    $vaultUser.Add("Template",$values[7])
                    $vaultUser.Add("GWAccount",$values[8])
                    $vaultUser.Add("Disabled",$values[9])
                    $vaultUser.Add("Type",$values[10])
                    $vaultUser.Add("UserID",$values[11])
                    $vaultUser.Add("LocationID",$values[12])
                    $vaultUser.Add("EnableComponentMonitoring",$values[13])
                    
                    #output object
                    new-object -Type psobject -Property $vaultUser | select Name, Quota, UsedQuota, 
                        Location, FirstName, LastName, LDAPUser, Template, GWAccount, Disabled, 
                            Type, UserID, LocationID, EnableComponentMonitoring
                
                }
            
            }
            
        }
    
    }
    
}

Function Get-UserActivity{

    <#
    .SYNOPSIS
    	This command generates a list of activities carried out in the specified 
        Vault for the user who issues this command. 
        The Safes included in the output are those to which the User carrying out 
        the command has authorization.

    .DESCRIPTION
    	Exposes the PACLI Function: "INSPECTUSER"

    .PARAMETER vault
        The name of the Vault to which the User has access
        
    .PARAMETER user
        The Username of the User issuing the command
        
    .PARAMETER logDays
        The number of days to include in the list of activities.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$False)][string]$vault,
        [Parameter(Mandatory=$False)][string]$user,
        [Parameter(Mandatory=$False)][int]$logDays,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
            
        #execute pacli with parameters
        $userActivity = (Invoke-Expression "$pacli INSPECTUSER $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'") | 
            
            #ignore whitespace lines
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"

            #if result(s) returned
            if($userActivity){
                
                #process each result
                foreach($activity in $userActivity){
                    
                    #define hash to hold values
                    $activities = @{}
                    
                    #split the command output
                    $values = $user | ConvertFrom-PacliOutput
                        
                    #assign values to properties
                    $activities.Add("Time",$values[0])
                    $activities.Add("User",$values[1])
                    $activities.Add("Safe",$values[2])
                    $activities.Add("Activity",$values[3])
                    $activities.Add("Location",$values[4])
                    $activities.Add("NewLocation",$values[5])
                    $activities.Add("RequestID",$values[6])
                    $activities.Add("RequestReason",$values[7])
                    $activities.Add("Code",$values[8])
                    
                    #output object
                    new-object -Type psobject -Property $activities | select Time, User, Safe, 
                        Activity, Location, NewLocation, RequestID, RequestReason, Code
                        
                }
            
            }
            
        }
        
    }
    
}

Function Get-SafesLog{

    <#
    .SYNOPSIS
    	Generates a log of activities per Safe in the specified Vault.

    .DESCRIPTION
    	Exposes the PACLI Function: "SAFESLOG"
    
    .PARAMETER vault 
    	The name of the Vault containing the Safe.
        
    .PARAMETER user 
	   The Username of the User carrying out the command.
    
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$False)][string]$vault,
        [Parameter(Mandatory=$False)][string]$user,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
            
        #execute pacli with parameters
        $safesLog = (Invoke-Expression "$pacli SAFESLOG $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'") | 
            
            #ignore whitespace lines
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"

            #if result(s) returned
            if($safesLog){
                
                #process each result
                foreach($safe in $safesLog){
                    
                    #define hash to hold values
                    $safeLogs = @{}
                    
                    #split the command output
                    $values = $safe | ConvertFrom-PacliOutput
                        
                    #assign values to properties
                    $safeLogs.Add("Name",$values[0])
                    $safeLogs.Add("UsersCount",$values[1])
                    $safeLogs.Add("OpenDate",$values[2])
                    $safeLogs.Add("OpenState",$values[3])
                    
                    #output object
                    new-object -Type psobject -Property $safeLogs | select Name, UsersCount, OpenDate, OpenState
                        
                }
            
            }
            
        }
        
    }
    
}

Function Clear-UserHistory{

    <#
    .SYNOPSIS
    	Clears the history records for Users of the specified Vault

    .DESCRIPTION
    	Exposes the PACLI Function: "CLEARUSERHISTORY"

    .PARAMETER vault 
    	The name of the Vault in which to clear the history records
        
    .PARAMETER user 
    	The Username of the User carrying out the command.
    
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
        
        $clearUserHistory = Invoke-Expression "$pacli CLEARUSERHISTORY $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Set-UserPhoto{

    <#
    .SYNOPSIS
    	Saves a User’s photo in the Vault.

    .DESCRIPTION
    	Exposes the PACLI Function: "PUTUSERPHOTO"
    
    .PARAMETER vault 
    	The name of the Vault to which the User has access.
        
    .PARAMETER user 
    	The Username of the User who is carrying out the command.
        
    .PARAMETER destUser 
    	The name of the User in the photograph.
        
    .PARAMETER localFolder 
    	The location of the folder in which the photograph is stored

    .PARAMETER localFile 
    	The name of the file in which the photograph is stored
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$destUser,
        [Parameter(Mandatory=$True)][string]$localFolder,
        [Parameter(Mandatory=$True)][string]$localFile,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
        
        $setUserPhoto = Invoke-Expression "$pacli PUTUSERPHOTO $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Get-UserPhoto{

    <#
    .SYNOPSIS
    	Retrieves the photograph of the specified CyberArk User from the Vault

    .DESCRIPTION
    	Exposes the PACLI Function: "GETUSERPHOTO"
    
    .PARAMETER vault 
    	The name of the Vault to which the User has access.
        
    .PARAMETER user 
    	The Username of the User who is carrying out the command.
        
    .PARAMETER destUser 
    	The name of the User whose photo you wish to retrieve.
        
    .PARAMETER localFolder 
    	The path of the folder in which the photograph is stored

    .PARAMETER localFile 
    	The name of the file in which the photograph is stored
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$destUser,
        [Parameter(Mandatory=$True)][string]$localFolder,
        [Parameter(Mandatory=$True)][string]$localFile,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
        
        $getUserPhoto = Invoke-Expression "$pacli GETUSERPHOTO $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Send-PAMailMessage{

    <#
    .SYNOPSIS
    	Enables a User to send e-mail using details in the User’s account

    .DESCRIPTION
    	Exposes the PACLI Function: "MAILUSER"

    .PARAMETER vault
	The name of the Vault to which the User has access.

    .PARAMETER user
	The Username of the User who is carrying out the command

    .PARAMETER mailServerIP
        The IP of the mail server
        
    .PARAMETER senderEmail
        The E-mail address of the sender. This is used as return address and in 
        the ‘From’ field of the mail.
        
    .PARAMETER domainName
        The sender’s domain (computer name). This value can usually be anything 
        other than blank.
        
    .PARAMETER recipientEmail
        The E-mail address of the recipient
        
    .PARAMETER recipientUser
        The recipient user in Vault=vault. The recipient’s E-mail is taken from
        the user’s personal details. From the home address/business address/other 
        address according to the following parameters

    .PARAMETER safe
        The outgoing E-mail will contain a link to this CyberArk Vault file.

    .PARAMETER folder
        The outgoing E-mail will contain a link to this CyberArk Vault file.
        
    .PARAMETER file
        The outgoing E-mail will contain a link to this CyberArk Vault file.
        
    .PARAMETER subject
        The subject of the E-mail message
            
    .PARAMETER text
        The text of the E-mail message
        
    .PARAMETER useBusinessMail
        Use the recipient user’s business Email address.

    .PARAMETER useHomeMail
        Use the recipient user’s Home Email address.

    .PARAMETER useOtherMail
        Use the recipient user’s other E-mail address.

    .PARAMETER templateFile
        The file path of a template for the Email to be sent. The template file
        may contain variables from this command only

    .PARAMETER parm1
        Values for variables in the template file.
        
    .PARAMETER parm2
        Values for variables in the template file.
        
    .PARAMETER parm3
        Values for variables in the template file.
        
    .PARAMETER parm4 
        Values for variables in the template file.
        
    .PARAMETER parm5
        Values for variables in the template file.
        
    .PARAMETER parm6
        Values for variables in the template file.
        
    .PARAMETER parm7
        Values for variables in the template file.
        
    .PARAMETER parm8
        Values for variables in the template file.
        
    .PARAMETER parm9
        Values for variables in the template file.
        
    .PARAMETER parm10
        Values for variables in the template file.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
        Example for template file content:
        Dear %%RecipientUser,
        I have sent you a new report named %%FILE in safe %%SAFE folder
        %%FOLDER. Please take the time to review it.
        Best Regards,
        %%PARM1.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$mailServerIP,
        [Parameter(Mandatory=$True)][string]$senderEmail,
        [Parameter(Mandatory=$True)][string]$domainName,
        [Parameter(Mandatory=$False)][string]$recipientEmail,
        [Parameter(Mandatory=$False)][string]$recipientUser,
        [Parameter(Mandatory=$False)][string]$safe,
        [Parameter(Mandatory=$False)][string]$folder,
        [Parameter(Mandatory=$False)][string]$file,
        [Parameter(Mandatory=$False)][string]$subject,
        [Parameter(Mandatory=$False)][string]$text,
        [Parameter(Mandatory=$False)][switch]$useBusinessMail,
        [Parameter(Mandatory=$False)][switch]$useHomeMail,
        [Parameter(Mandatory=$False)][switch]$useOtherMail,
        [Parameter(Mandatory=$False)][string]$templateFile,
        [Parameter(Mandatory=$False)][string]$parm1,
        [Parameter(Mandatory=$False)][string]$parm2,
        [Parameter(Mandatory=$False)][string]$parm3,
        [Parameter(Mandatory=$False)][string]$parm4, 
        [Parameter(Mandatory=$False)][string]$parm5,
        [Parameter(Mandatory=$False)][string]$parm6,
        [Parameter(Mandatory=$False)][string]$parm7,
        [Parameter(Mandatory=$False)][string]$parm8,
        [Parameter(Mandatory=$False)][string]$parm9,
        [Parameter(Mandatory=$False)][string]$parm10,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
            
        $mailUser = Invoke-Expression "$pacli MAILUSER $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Add-SafeShare{

    <#
    .SYNOPSIS
    	Shares a Safe through a Gateway account

    .DESCRIPTION
    	Exposes the PACLI Function: "ADDSAFESHARE"

    .PARAMETER vault
	   The name of the Vault to which the User has access.

    .PARAMETER user
	   The Username of the User carrying out the task.

    .PARAMETER safe
	   The Safe to share through the Gateway

    .PARAMETER gwAccount
	   The name of the Gateway account through which the Safe is shared
    
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$gwAccount,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                
        [array]$addSafeShare = (Invoke-Expression "$pacli ADDSAFESHARE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)" -ErrorAction SilentlyContinue) 2>&1

        if($LASTEXITCODE){

            write-debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "Error Sharing Safe: $safe"
            write-debug $($addSafeShare[0]|out-string)
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "$safe Shared via $gwAccount"
            
        }
        
    }

}

Function Remove-SafeShare{

    <#
    .SYNOPSIS
    	Removes the safe sharing feature through a specific Gateway account. 
        This means that this Safe will no longer be accessible through this 
        Gateway account.

    .DESCRIPTION
    	Exposes the PACLI Function: "DELETESAFESHARE"

    .PARAMETER vault
	   The Vault containing the shared Safe.

    .PARAMETER user
	   The Username of the User carrying out the task.

    .PARAMETER safe
	   The Safe from which to remove the sharing feature.

    .PARAMETER gwAccount
	   The name of the Gateway account through which the Safe will not be accessible.
    
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$gwAccount,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                
        [array]$deleteSafeShare = (Invoke-Expression "$pacli DELETESAFESHARE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)" -ErrorAction SilentlyContinue) 2>&1

        if($LASTEXITCODE){

            write-debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "Error Deleting Sharing Safe: $safe"
            write-debug $($deleteSafeShare[0]|out-string)
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "$safe Share via $gwAccount Deleted"
            
        }
        
    }

}

Function Add-Group{

    <#
    .SYNOPSIS
    	Adds a group to the CyberArk Vault

    .DESCRIPTION
    	Exposes the PACLI Function: "ADDGROUP"

    .PARAMETER vault
		The name of the Vault to which the User has access.

    .PARAMETER user
		The Username of the User who is carrying out the command

    .PARAMETER group
		The name of the group to add.

    .PARAMETER location
		The location in which to add the group.
		Note: Add a backslash ‘\’ before the name of the location.

    .PARAMETER description
		A brief description of the group.

    .PARAMETER externalGroup
		The name of an external group that is a member in the current group.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$group,
        [Parameter(Mandatory=$True)][string]$location,
        [Parameter(Mandatory=$False)][string]$description,
        [Parameter(Mandatory=$False)][string]$externalGroup,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                
        $addGroup = Invoke-Expression "$pacli ADDGROUP $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Update-Group{

    <#
    .SYNOPSIS
    	Updates CyberArk Group properties.

    .DESCRIPTION
    	Exposes the PACLI Function: "UPDATEGROUP"

    .PARAMETER vault
		The name of the Vault in which the group is defined

    .PARAMETER user
		The Username of the User who is carrying out the command

    .PARAMETER group
		The name of the group to update.

    .PARAMETER location
		The name of the location containing the group
		Note: Add a backslash ‘\’ before the name of the location.

    .PARAMETER description
		The description of the group.

    .PARAMETER externalGroup
		The name of an external group that is a member in the current group.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$group,
        [Parameter(Mandatory=$True)][string]$location,
        [Parameter(Mandatory=$False)][string]$description,
        [Parameter(Mandatory=$False)][string]$externalGroup,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                
        $updateGroup = Invoke-Expression "$pacli UPDATEGROUP $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Remove-Group{

    <#
    .SYNOPSIS
    	Deletes a CyberArk group from the Vault

    .DESCRIPTION
    	Exposes the PACLI Function: "DELETEGROUP"

    .PARAMETER vault
		The name of the Vault containing the group.

    .PARAMETER user
		The Username of the User who is carrying out the command

    .PARAMETER group
		The name of the group to delete.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$group,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                
        $removeGroup = Invoke-Expression "$pacli DELETEGROUP $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Add-GroupMember{

    <#
    .SYNOPSIS
    	Adds a CyberArk User to an existing CyberArk group

    .DESCRIPTION
    	Exposes the PACLI Function: "ADDGROUPMEMBER"

    .PARAMETER vault
		The name of the Vault containing the group.

    .PARAMETER user
		The Username of the User who is carrying out the command

    .PARAMETER group
		The name of the group.
    
    .PARAMETER member
        The name of the User to add to the group.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$group,
        [Parameter(Mandatory=$True)][string]$member,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                
        $addGroupMember = Invoke-Expression "$pacli ADDGROUPMEMBER $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Remove-GroupMember{

    <#
    .SYNOPSIS
    	Removes a User as a member from a CyberArk group.

    .DESCRIPTION
    	Exposes the PACLI Function: "DELETEGROUPMEMBER"

    .PARAMETER vault
		The name of the Vault containing the group.

    .PARAMETER user
		The Username of the User who is carrying out the command

    .PARAMETER group
		The name of the group.
    
    .PARAMETER member
        The name of the group member to delete
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$group,
        [Parameter(Mandatory=$True)][string]$member,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                
        $removeGroupMember = Invoke-Expression "$pacli REMOVEGROUPMEMBER $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Add-Location{

    <#
    .SYNOPSIS
    	Adds a location to the Vault.

    .DESCRIPTION
    	Exposes the PACLI Function: "ADDLOCATION"

    .PARAMETER vault
        The name of the Vault to which the User has access.
    
    .PARAMETER user
        The Username of the User who is carrying out the command.
        
    .PARAMETER location
        The name of the location to add.
        Note: Add a backslash ‘\’ before the name of the location
        
    .PARAMETER quota
        The size of the quota to allocate to the location in MB. 
        The specification ‘-1’ indicates an unlimited quota allocation.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$location,
        [Parameter(Mandatory=$False)][int]$quota,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                
        $addLocation = Invoke-Expression "$pacli ADDLOCATION $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Update-Location{

    <#
    .SYNOPSIS
    	Updates the properties of a location.

    .DESCRIPTION
    	Exposes the PACLI Function: "UPDATELOCATION"

    .PARAMETER vault
        The name of the Vault to which the User has access.
    
    .PARAMETER user
        The Username of the User who is carrying out the command.
        
    .PARAMETER location
        The name of the location to update.
        Note: Add a backslash ‘\’ before the name of the location
        
    .PARAMETER quota
        The size of the quota to allocate to the location in MB. 
        The specification ‘-1’ indicates an unlimited quota allocation.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$location,
        [Parameter(Mandatory=$True)][int]$quota,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                
        $updateLocation = Invoke-Expression "$pacli UPDATELOCATION $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Rename-Location{

    <#
    .SYNOPSIS
    	Renames a Location.

    .DESCRIPTION
    	Exposes the PACLI Function: "RENAMELOCATION"

    .PARAMETER vault
        The name of the Vault to which the User has access.
    
    .PARAMETER user
        The Username of the User who is carrying out the command.
        
    .PARAMETER location
        The current name of the Location to rename.
        Note: Add a backslash ‘\’ before the name of the location
        
    .PARAMETER newName
        The new name of the Location.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$location,
        [Parameter(Mandatory=$True)][int]$newName,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                
        $renameLocation = Invoke-Expression "$pacli RENAMELOCATION $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Remove-Location{

    <#
    .SYNOPSIS
    	Deletes a Location

    .DESCRIPTION
    	Exposes the PACLI Function: "DELETELOCATION"

    .PARAMETER vault
        The name of the Vault to which the User has access.
    
    .PARAMETER user
        The Username of the User who is carrying out the command.
        
    .PARAMETER location
        The name of the location to delete.
        Note: Add a backslash ‘\’ before the name of the location
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$location,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                
        $removeLocation = Invoke-Expression "$pacli DELETELOCATION $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Get-Locations{

    <#
    .SYNOPSIS
    	Generates a list of locations, and their allocated quotas.

    .DESCRIPTION
    	Exposes the PACLI Function: "LOCATIONSLIST"

    .PARAMETER vault
       The name of the Vault in which the location is defined.
    
    .PARAMETER user
        The Username of the User who is carrying out the command.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                
        #execute pacli with parameters
        $locations = (Invoke-Expression "$pacli LOCATIONSLIST $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'") | 
            
            #ignore whitespace lines
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"

            #if result(s) returned
            if($locations){
                
                #process each result
                foreach($location in $locations){
                    
                    #define hash to hold values
                    $locationsList = @{}
                    
                    #split the command output
                    $values = $safe | ConvertFrom-PacliOutput
                        
                    #assign values to properties
                    $locationsList.Add("Name",$values[0])
                    $locationsList.Add("Quota",$values[1])
                    $locationsList.Add("UsedQuota",$values[2])
                    $locationsList.Add("LocationID",$values[3])
                    
                    #output object
                    new-object -Type psobject -Property $locationsList | select Name, Quota, UsedQuota, LocationID
                        
                }
            
            }
            
        }
        
    }
    
}

Function Get-GroupDetails{

    <#
    .SYNOPSIS
    	Displays the description of a CyberArk group.

    .DESCRIPTION
    	Exposes the PACLI Function: "GROUPDETAILS"

    .PARAMETER vault
       The name of the Vault in which the group is defined.
    
    .PARAMETER user
        The Username of the User who is carrying out the command.

    .PARAMETER group
        The name of the group
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$group,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        #execute pacli with parameters
        $groupDetails = (Invoke-Expression "$pacli GROUPDETAILS $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'") | 
            
            #ignore whitespace lines
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"

            #if result(s) returned
            if($groupDetails){
                
                #process each result
                foreach($detail in $groupDetails){
                    
                    #define hash to hold values
                    $groupDetail = @{}
                    
                    #split the command output
                    $values = $detail | ConvertFrom-PacliOutput
                        
                    #assign values to properties
                    $groupDetail.Add("Description",$values[0])
                    $groupDetail.Add("LDAPFullDN",$values[1])
                    $groupDetail.Add("LDAPDirectory",$values[2])
                    $groupDetail.Add("MapID",$values[3])
                    $groupDetail.Add("MapName",$values[4])
                    $groupDetail.Add("ExternalGroup",$values[5])
                    
                    #output object
                    new-object -Type psobject -Property $groupDetail | select Description, LDAPFullDN, LDAPDirectory, MapID,
                        MapName, ExternalGroup
                        
                }
            
            }
            
        }
        
    }
    
}

Function Get-GroupMembers{

    <#
    .SYNOPSIS
    	Lists the members of a specified CyberArk group

    .DESCRIPTION
    	Exposes the PACLI Function: "GROUPMEMBERS"

    .PARAMETER vault
       The name of the Vault in which the group is defined.
    
    .PARAMETER user
        The Username of the User who is carrying out the command.

    .PARAMETER group
        The name of the group
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$group,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        #execute pacli with parameters
        $groupMembers = (Invoke-Expression "$pacli GROUPMEMBERS $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'") | 
            
            #ignore whitespace lines
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"

            #if result(s) returned
            if($groupMembers){
                
                #process each result
                foreach($member in $groupMembers){
                    
                    #define hash to hold values
                    $groupMember = @{}
                    
                    #split the command output
                    $values = $member | ConvertFrom-PacliOutput
                        
                    #assign values to properties
                    $groupMember.Add("Name",$values[0])
                    $groupMember.Add("UserID",$values[1])
                    
                    #output object
                    new-object -Type psobject -Property $groupMember | select Name, UserID
                        
                }
            
            }
            
        }
        
    }
    
}

Function Add-LDAPBranch{

    <#
    .SYNOPSIS
    	Adds an LDAP branch to an existing CyberArk Directory Map

    .DESCRIPTION
    	Exposes the PACLI Function: "LDAPBRANCHADD"

    .PARAMETER vault 
		The name of the Vault.

    .PARAMETER user 
		The Username of the User who is logged on.

    .PARAMETER ldapMapName 
		The name of the Directory Map where the LDAP branch will be added.

    .PARAMETER ldapDirName 
		The name of the LDAP directory.

    .PARAMETER ldapBranchName 
		The DN of the LDAP directory branch.

    .PARAMETER ldapQuery 
		The LDAP filter that is applied to objects in the specified branch.

    .PARAMETER ldapGroupMatch 
		A regular expression used to filter LDAP groups of objects in the branch.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$ldapMapName,
        [Parameter(Mandatory=$True)][string]$ldapDirName,
        [Parameter(Mandatory=$True)][string]$ldapBranchName,
        [Parameter(Mandatory=$False)][string]$ldapQuery,
        [Parameter(Mandatory=$False)][string]$ldapGroupMatch,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        #execute pacli with parameters
        $addLDAPBranch = (Invoke-Expression "$pacli LDAPBRANCHADD $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'") | 
            
            #ignore whitespace lines
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"

            #if result(s) returned
            if($addLDAPBranch){
                
                #process each result
                foreach($branch in $addLDAPBranch){
                    
                    #define hash to hold values
                    $ldapBranch = @{}
                    
                    #split the command output
                    $values = $branch | ConvertFrom-PacliOutput
                        
                    #assign values to properties
                    $ldapBranch.Add("LDAPBranchID",$values[0])
                    $ldapBranch.Add("LDAPMapID",$values[1])
                    $ldapBranch.Add("LDAPMapName",$values[2])
                    $ldapBranch.Add("LDAPDirName",$values[3])
                    $ldapBranch.Add("LDAPBranchName",$values[4])
                    $ldapBranch.Add("LDAPQuery",$values[5])
                    $ldapBranch.Add("LDAPGroupMatch",$values[6])
                    
                    #output object
                    new-object -Type psobject -Property $ldapBranch | select LDAPBranchID, LDAPMapID, LDAPMapName, LDAPDirName,
                        LDAPBranchName, LDAPQuery, LDAPGroupMatch
                        
                }
            
            }
            
        }
        
    }
    
}

Function Update-LDAPBranch{

    <#
    .SYNOPSIS
    	Updates an existing LDAP branch in a CyberArk Directory Map

    .DESCRIPTION
    	Exposes the PACLI Function: "LDAPBRANCHUPDATE"

    .PARAMETER vault 
		The name of the Vault.

    .PARAMETER user 
		The Username of the User who is logged on.

    .PARAMETER ldapMapName
		The name of the Directory Map where the LDAP branch will be updated.

    .PARAMETER updateBranchID
		A 64-bit unique ID of the branch to update       

    .PARAMETER ldapDirName 
		The name of the LDAP directory.

    .PARAMETER ldapBranchName 
		The DN of the LDAP directory branch.

    .PARAMETER ldapQuery 
		The LDAP filter that is applied to objects in the specified branch.

    .PARAMETER ldapGroupMatch 
		A regular expression used to filter LDAP groups of objects in the branch.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$ldapMapName,
        [Parameter(Mandatory=$True)][string]$updateBranchID,
        [Parameter(Mandatory=$True)][string]$ldapDirName,
        [Parameter(Mandatory=$True)][string]$ldapBranchName,
        [Parameter(Mandatory=$False)][string]$ldapQuery,
        [Parameter(Mandatory=$False)][string]$ldapGroupMatch,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                        
        #execute pacli with parameters
        $updateLDAPBranch = (Invoke-Expression "$pacli LDAPBRANCHUPDATE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'") | 
            
            #ignore whitespace lines
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"

            #if result(s) returned
            if($updateLDAPBranch){
                
                #process each result
                foreach($branch in $updateLDAPBranch){
                    
                    #define hash to hold values
                    $ldapBranch = @{}
                    
                    #split the command output
                    $values = $branch | ConvertFrom-PacliOutput
                        
                    #assign values to properties
                    $ldapBranch.Add("LDAPBranchID",$values[0])
                    $ldapBranch.Add("LDAPMapID",$values[1])
                    $ldapBranch.Add("LDAPMapName",$values[2])
                    $ldapBranch.Add("LDAPDirName",$values[3])
                    $ldapBranch.Add("LDAPBranchName",$values[4])
                    $ldapBranch.Add("LDAPQuery",$values[5])
                    $ldapBranch.Add("LDAPGroupMatch",$values[6])
                    
                    #output object
                    new-object -Type psobject -Property $ldapBranch | select LDAPBranchID, LDAPMapID, LDAPMapName, LDAPDirName,
                        LDAPBranchName, LDAPQuery, LDAPGroupMatch
                        
                }
            
            }
            
        }
    
    }
    
}

Function Remove-LDAPBranch{

    <#
    .SYNOPSIS
    	Deletes an LDAP branch from a CyberArk Directory Map

    .DESCRIPTION
    	Exposes the PACLI Function: "LDAPBRANCHDELETE"

    .PARAMETER vault 
		The name of the Vault.

    .PARAMETER user 
		The Username of the User who is logged on.

    .PARAMETER ldapMapName
		The name of the Directory Map where the LDAP branch will be updated.

    .PARAMETER deleteBranchID
		A 64-bit unique ID of the branch to update       

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$ldapMapName,
        [Parameter(Mandatory=$True)][string]$deleteBranchID,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        #execute pacli with parameters
        $removeLDAPBranch = (Invoke-Expression "$pacli LDAPBRANCHDELETE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'") | 
            
            #ignore whitespace lines
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"

            #if result(s) returned
            if($removeLDAPBranch){
                
                #process each result
                foreach($branch in $removeLDAPBranch){
                    
                    #define hash to hold values
                    $ldapBranch = @{}
                    
                    #split the command output
                    $values = $branch | ConvertFrom-PacliOutput
                        
                    #assign values to properties
                    $ldapBranch.Add("LDAPBranchID",$values[0])
                    $ldapBranch.Add("LDAPMapID",$values[1])
                    $ldapBranch.Add("LDAPMapName",$values[2])
                    $ldapBranch.Add("LDAPDirName",$values[3])
                    $ldapBranch.Add("LDAPBranchName",$values[4])
                    $ldapBranch.Add("LDAPQuery",$values[5])
                    $ldapBranch.Add("LDAPGroupMatch",$values[6])
                    
                    #output object
                    new-object -Type psobject -Property $ldapBranch | select LDAPBranchID, LDAPMapID, LDAPMapName, LDAPDirName,
                        LDAPBranchName, LDAPQuery, LDAPGroupMatch
                        
                }
            
            }
            
        }
        
    }
    
}

Function Get-LDAPBranches{

    <#
    .SYNOPSIS
    	Lists the LDAP branches in a specified CyberArk Directory Map

    .DESCRIPTION
    	Exposes the PACLI Function: "LDAPBRANCHESLIST"

    .PARAMETER vault 
		The name of the Vault.

    .PARAMETER user 
		The Username of the User who is logged on.

    .PARAMETER ldapMapName
		The name of the Directory Map which contains the branches that will be listed.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$ldapMapName,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        #execute pacli with parameters
        $getLDAPBranches = (Invoke-Expression "$pacli LDAPBRANCHESLIST $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'") | 
            
            #ignore whitespace lines
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"

            #if result(s) returned
            if($getLDAPBranches){
                
                #process each result
                foreach($branch in $getLDAPBranches){
                    
                    #define hash to hold values
                    $ldapBranch = @{}
                    
                    #split the command output
                    $values = $branch | ConvertFrom-PacliOutput
                        
                    #assign values to properties
                    $ldapBranch.Add("LDAPBranchID",$values[0])
                    $ldapBranch.Add("LDAPMapID",$values[1])
                    $ldapBranch.Add("LDAPMapName",$values[2])
                    $ldapBranch.Add("LDAPDirName",$values[3])
                    $ldapBranch.Add("LDAPBranchName",$values[4])
                    $ldapBranch.Add("LDAPQuery",$values[5])
                    $ldapBranch.Add("LDAPGroupMatch",$values[6])
                    
                    #output object
                    new-object -Type psobject -Property $ldapBranch | select LDAPBranchID, LDAPMapID, LDAPMapName, LDAPDirName,
                        LDAPBranchName, LDAPQuery, LDAPGroupMatch
                        
                }
            
            }
            
        }
        
    }
    
}

###Safe Functions###

Function Add-NetworkArea{

    <#
    .SYNOPSIS
    	Adds a new Network Area to the CyberArk Vault environment.

    .DESCRIPTION
    	Exposes the PACLI Function: "ADDNETWORKAREA"

    .PARAMETER vault
        The name of the Vault to which the Network Area will be added.
        
    .PARAMETER user
        The name of the User carrying out the task.
        
    .PARAMETER networkArea
        The name of the new Network Area.
        
    .PARAMETER securityLevelParm
        The level of the Network Area security flags.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$networkArea,
        [Parameter(Mandatory=$False)][string]$securityLevelParm,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $addNetworkArea = Invoke-Expression "$pacli ADDNETWORKAREA $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Remove-NetworkArea{

    <#
    .SYNOPSIS
    	Deletes a Network Area from the CyberArk Vault environment.

    .DESCRIPTION
    	Exposes the PACLI Function: "DELETENETWORKAREA"

    .PARAMETER vault
        The name of the Vault from which the Network Area will be deleted.
        
    .PARAMETER user
        The name of the User carrying out the task.
        
    .PARAMETER networkArea
        The name of the Network Area to delete.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$networkArea,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $removeNetworkArea = Invoke-Expression "$pacli DELETENETWORKAREA $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Move-NetworkArea{

    <#
    .SYNOPSIS
    	Moves a Network Area to a new location in the Network Areas tree.

    .DESCRIPTION
    	Exposes the PACLI Function: "MOVENETWORKAREA"

    .PARAMETER vault
        The name of the Vault to which the Network Area will be added.
        
    .PARAMETER user
        The name of the User carrying out the task.
        
    .PARAMETER networkArea
        The name of the Network Area.
        
    .PARAMETER newLocation
        The new location of the Network Area.
        Note: Add a backslash ‘\’ before the name of the location.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$networkArea,
        [Parameter(Mandatory=$True)][string]$newLocation,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $moveNetworkArea = Invoke-Expression "$pacli MOVENETWORKAREA $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Rename-NetworkArea{

    <#
    .SYNOPSIS
    	Renames an existing Network Area.

    .DESCRIPTION
    	Exposes the PACLI Function: "RENAMENETWORKAREA"

    .PARAMETER vault
        The name of the Vault to which the Network Area will be added.
        
    .PARAMETER user
        The name of the User carrying out the task.
        
    .PARAMETER networkArea
        The name of the Network Area.
        
    .PARAMETER newName
        The new name of the Network Area.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$networkArea,
        [Parameter(Mandatory=$True)][string]$newName,
        [Parameter(Mandatory=$False)][int]$sessionID
    )
    
    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $renameNetworkArea = Invoke-Expression "$pacli RENAMENETWORKAREA $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Get-NetworkArea{

    <#
    .SYNOPSIS
    	Lists all of the Network Areas that are defined in the Vault.

    .DESCRIPTION
    	Exposes the PACLI Function: "NETWORKAREASLIST"

    .PARAMETER vault
        The name of the Vault in which the Network Area is defined.
        
    .PARAMETER user
        The name of the User carrying out the task.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        #execute pacli with parameters
        $getNetworkArea = (Invoke-Expression "$pacli NETWORKAREASLIST $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'") | 
            
            #ignore whitespace lines
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"

            #if result(s) returned
            if($getNetworkArea){
                
                #process each result
                foreach($area in $getNetworkArea){
                    
                    #define hash to hold values
                    $networkArea = @{}
                    
                    #split the command output
                    $values = $area | ConvertFrom-PacliOutput
                        
                    #assign values to properties
                    $networkArea.Add("Name",$values[0])
                    $networkArea.Add("SecurityLevel",$values[1])
                    
                    #output object
                    new-object -Type psobject -Property $networkArea | select Name, SecurityLevel
                        
                }
            
            }
            
        }
        
    }
    
}

Function Add-AreaAddress{

    <#
    .SYNOPSIS
    	Adds an IP address to an existing Network Area.

    .DESCRIPTION
    	Exposes the PACLI Function: "ADDAREAADDRESS"

    .PARAMETER vault
        The name of the Vault in which the Network Area is defined.
        
    .PARAMETER user
        The name of the User carrying out the task.

    .PARAMETER networkArea
        The name of the Network Area to which to add an IP address
        
    .PARAMETER ipAddress
        The IP address to add to the Network Area.
        
    .PARAMETER ipMask
        The first IP address in the IP mask to add to the Network Area.
        
    .PARAMETER toAddress
        The final IP address in the mask of the Network Area.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$networkArea,
        [Parameter(Mandatory=$True)][string]$ipAddress,
        [Parameter(Mandatory=$False)][string]$ipMask,
        [Parameter(Mandatory=$True)][string]$toAddress,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $addAreaAddress = Invoke-Expression "$pacli ADDAREAADDRESS $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Remove-AreaAddress{

    <#
    .SYNOPSIS
    	Deletes an IP address from an existing Network Area.

    .DESCRIPTION
    	Exposes the PACLI Function: "DELETEAREAADDRESS"

    .PARAMETER vault
        The name of the Vault in which the Network Area is defined.
        
    .PARAMETER user
        The name of the User carrying out the task.

    .PARAMETER networkArea
        The name of the Network Area from which to delete an IP address
        
    .PARAMETER ipAddress
        The IP address to delete from the Network Area.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$networkArea,
        [Parameter(Mandatory=$True)][string]$ipAddress,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $removeAreaAddress = Invoke-Expression "$pacli DELETEAREAADDRESS $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Add-TrustedNetworkArea{

    <#
    .SYNOPSIS
    	Adds a Trusted Network Area from which a CyberArk User can access the 
        CyberArk Vault.

    .DESCRIPTION
    	Exposes the PACLI Function: "ADDTRUSTEDNETWORKAREA"

    .PARAMETER vault 
	   The name of the Vault to which to add the Trusted Network Area.
       
    .PARAMETER user 
	   The name of the User carrying out the task.
    
    .PARAMETER trusterName 
	   The User who will have access to the Trusted Network Area.
    
    .PARAMETER networkArea 
	   The name of the Trusted Network Area to add.
    
    .PARAMETER fromHour 
	   The time from which access to the Vault is permitted.
    
    .PARAMETER toHour 
	   The time until which access to the Vault is permitted.
    
    .PARAMETER maxViolationCount
	   The maximum number of access violations permitted before the User is not 
       permitted to access the Vault.
    
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$trusterName,
        [Parameter(Mandatory=$True)][string]$networkArea,
        [Parameter(Mandatory=$False)][int]$fromHour,
        [Parameter(Mandatory=$False)][int]$toHour,
        [Parameter(Mandatory=$False)][int]$maxViolationCount,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $addTrustedNetworkArea = Invoke-Expression "$pacli ADDTRUSTEDNETWORKAREA $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Remove-TrustedNetworkArea{

    <#
    .SYNOPSIS
    	Deletes a Trusted Network Area from a CyberArk Vault environment.

    .DESCRIPTION
    	Exposes the PACLI Function: "DELETETRUSTEDNETWORKAREA"

    .PARAMETER vault 
	   The name of the Vault in which the Trusted Network Area is defined.
       
    .PARAMETER user 
	   The name of the User carrying out the task.
    
    .PARAMETER trusterName 
	   The User whose access to the Trusted Network Area will be removed.
    
    .PARAMETER networkArea 
	   The name of the Trusted Network Area to delete.
    
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$trusterName,
        [Parameter(Mandatory=$True)][string]$networkArea,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $removeTrustedNetworkArea = Invoke-Expression "$pacli REMOVETRUSTEDNETWORKAREA $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Get-TrustedNetworkArea{

    <#
    .SYNOPSIS
    	Lists Trusted Network Areas

    .DESCRIPTION
    	Exposes the PACLI Function: "TRUSTEDNETWORKAREALIST"

    .PARAMETER vault 
	   The name of the Vault in which the Trusted Network Area is defined.
       
    .PARAMETER user 
	   The name of the User carrying out the task.
    
    .PARAMETER trusterName 
	   The User who has access to the Trusted Network Area
    
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$trusterName,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        #execute pacli with parameters
        $getTrustedNetworkArea = (Invoke-Expression "$pacli TRUSTEDNETWORKAREASLIST $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'") | 
            
            #ignore whitespace lines
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"

            #if result(s) returned
            if($getTrustedNetworkArea){
                
                #process each result
                foreach($area in $getTrustedNetworkArea){
                    
                    #define hash to hold values
                    $trustedNetworkArea = @{}
                    
                    #split the command output
                    $values = $area | ConvertFrom-PacliOutput
                        
                    #assign values to properties
                    $trustedNetworkArea.Add("Name",$values[0])
                    $trustedNetworkArea.Add("FromHour",$values[1])
                    $trustedNetworkArea.Add("ToHour",$values[2])
                    $trustedNetworkArea.Add("Active",$values[3])
                    $trustedNetworkArea.Add("MaxViolationCount",$values[4])
                    $trustedNetworkArea.Add("ViolationCount",$values[5])
                    
                    #output object
                    new-object -Type psobject -Property $trustedNetworkArea | select Name, FromHour, ToHour, Active, MaxViolationCount, ViolationCount
                        
                }
            
            }
            
        }
        
    }
    
}

Function Enable-TrustedNetworkArea{

    <#
    .SYNOPSIS
    	Activates a Trusted Network Area.

    .DESCRIPTION
    	Exposes the PACLI Function: "ACTIVATETRUSTEDNETWORKAREA"

    .PARAMETER vault 
	   The name of the Vault in which the Trusted Network Area is defined.
       
    .PARAMETER user 
	   The name of the User carrying out the task.
    
    .PARAMETER trusterName 
	   The User who will have access to the Trusted Network Area

    .PARAMETER networkArea 
	   The name of the Trusted Network Area to activate.
           
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.
        
    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$trusterName,
        [Parameter(Mandatory=$True)][string]$networkArea,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $enableTrustedNetworkArea = Invoke-Expression "$pacli ACTIVATETRUSTEDNETWORKAREA $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Disable-TrustedNetworkArea{

    <#
    .SYNOPSIS
    	Deactivates a Trusted Network Area.

    .DESCRIPTION
    	Exposes the PACLI Function: "DEACTIVATETRUSTEDNETWORKAREA"

    .PARAMETER vault 
	   The name of the Vault in which the Trusted Network Area is defined.
       
    .PARAMETER user 
	   The name of the User carrying out the task.
    
    .PARAMETER trusterName 
	   The User who will not have access to the Trusted Network Area.

    .PARAMETER networkArea 
	   The name of the Network Area to deactivate.
           
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$trusterName,
        [Parameter(Mandatory=$True)][string]$networkArea,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                        
        $disableTrustedNetworkArea = Invoke-Expression "$pacli DEACTIVATETRUSTEDNETWORKAREA $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

###Safe Functions###

Function Open-Safe{

    <#
    .SYNOPSIS
    	Open a Safe (Safe Owner authorizations required). When the Safe is opened, 
        various details about the Safe will be displayed, depending on the 
        parameters specified.

    .DESCRIPTION
    	Exposes the PACLI Function: "OPENSAFE"
        
    .PARAMETER vault
		The name of the Vault containing the Safes to open.

    .PARAMETER user
		The Username of the User carrying out the task.

    .PARAMETER safe
		The name of the Safe to open.

    .PARAMETER requestUsageType
		The operation that the user will carry out. 
        
        Possible options are:
            REQUEST_AND_USE – create and send a request if
            necessary, or use the confirmation if it has been granted to
            open the Safe/file/password.
		
            CHECK_DON’T_USE – check if a request has been sent or,
            if not, create one and send an error. If a request is not
            needed, carry out the action.
            
            USE_ONLY – if the request has been confirmed, or if a
            request is not needed, open the Safe/file/password.
            
		Note: In version 4.1, this parameter has no default value and
		is obsolete. However, it can still be used as long as the
		‘userequest’, ‘sendrequest’ and ‘executerequest’ parameters
		are not specified.

    .PARAMETER requestAccessType
		Whether the request is for a single or multiple access.
		Possible options are:
		  SINGLE – for a single access.
          
		  MULTIPLE – for multiple accesses.

    .PARAMETER usableFrom
		The proposed date from when the request will be valid.

    .PARAMETER usableTo
		The proposed date until when the request will be valid.

    .PARAMETER requestReason
		The reason for the request.

    .PARAMETER useRequest
		If a confirmed request exists, it will be used.

    .PARAMETER sendRequest
		A request will be sent, if needed.

    .PARAMETER executeRequest
		The action will be executed, if a confirmation exists or is not
		needed.
    
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$False)][ValidateSet("REQUEST_AND_USE","CHECK_DON’T_USE","USE_ONLY")][string]$requestUsageType,
        [Parameter(Mandatory=$False)][ValidateSet("SINGLE","MULTIPLE")][string]$requestAccessType,
        [Parameter(Mandatory=$False)][string]$usableFrom,
        [Parameter(Mandatory=$False)][string]$usableTo,
        [Parameter(Mandatory=$False)][string]$requestReason,
        [Parameter(Mandatory=$False)][switch]$useRequest,
        [Parameter(Mandatory=$False)][switch]$sendRequest,
        [Parameter(Mandatory=$False)][switch]$executeRequest,
        [Parameter(Mandatory=$False)][int]$sessionID
    )


    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                        
        $openSafe = (Invoke-Expression "$pacli OPENSAFE OUTPUT '(ALL,ENCLOSE)' $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) ") | 
            
            #ignore whitespace lines
            Select-String -Pattern "\S"

        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            #error openeing safe, return false

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            
            #if safe opened/results returned
            if($openSafe){
            
                #process returned results
                foreach($safe in $openSafe){
                    
                    #define hash to hold values
                    $openedSafe = @{}
                    
                    #split the command output
                    $values = $safe | ConvertFrom-PacliOutput
                    
                    #assign values to properties
                    #(these may not be the correct order - but most are)
                    $openedSafe.Add("Name",$values[0])
                    $openedSafe.Add("Status",$values[1])
                    $openedSafe.Add("LastUsed",$values[2])
                    $openedSafe.Add("Accessed",$values[3])
                    $openedSafe.Add("Size",$values[4])
                    $openedSafe.Add("Location",$values[5])
                    $openedSafe.Add("SafeID",$values[6])
                    $openedSafe.Add("LocationID",$values[7])
                    $openedSafe.Add("TextOnly",$values[8])
                    $openedSafe.Add("ShareOptions",$values[9])
                    $openedSafe.Add("UseFileCategories",$values[10])
                    $openedSafe.Add("RequireContentValidation",$values[11])
                    $openedSafe.Add("RequireReason",$values[12])
                    $openedSafe.Add("EnforceExclusivePasswords",$values[13])
                    
                    #output object
                    new-object -Type psobject -Property $openedSafe | select Name, Size, Status, LastUsed, 
                        Accessed, ShareOptions, Location, UseFileCategories, TextOnly, RequireReason, 
                            EnforceExclusivePasswords, RequireContentValidation, SafeID, LocationID
                
                }
            
            }
            
        }
    
    }
    
}

Function Close-Safe{

    <#
    .SYNOPSIS
    	Closes a Safe

    .DESCRIPTION
    	Exposes the PACLI Function: "CLOSESAFE"

    .PARAMETER vault
		The name of the Vault containing the Safes to close.

    .PARAMETER user
		The Username of the User carrying out the task.

    .PARAMETER safe
		The name of the Safe to close.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$False)][int]$sessionID
    )
    
    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $closeSafe = (Invoke-Expression "$pacli CLOSESAFE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1

        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }
    
}

Function Add-Safe{

    <#
    .SYNOPSIS
    	Adds a Safe. Via the parameters, declare which Vault the Safe will be in, 
        the size of the Safe, and the file history that the Safe will retain.

    .DESCRIPTION
    	Exposes the PACLI Function: "ADDSAFE"

    .PARAMETER vault
        The Vault to which the Safe will be added
        
    .PARAMETER user
        The Username of the User who is adding the Safe
        
    .PARAMETER safe
        The name of the Safe to be added.
        
    .PARAMETER location
        The location in which to add the Safe.
        Note: Add a backslash ‘\’ before the name of the location.
        
    .PARAMETER size
        The size in MB of the Safe to add
        
    .PARAMETER description
        A description of the Safe.
        
    .PARAMETER fromHour
        The time from which Users can access the Safe.
        
    .PARAMETER toHour
        The time until which Users can access the Safe.
        
    .PARAMETER delay
        The delay in minutes between the User opening the Safe and the Vault 
        permitting access to it.

    .PARAMETER dailyVersions
        The number of daily versions of files to be retained.
        
    .PARAMETER monthlyVersions
        The number of monthly versions of files to be retained.
        
    .PARAMETER yearlyVersions
        The number of yearly versions of files to be retained.
        
    .PARAMETER logRetention
        The number of days that must pass before log files can be completely 
        deleted from the Safe.

    .PARAMETER fileRetention
        The number of days that must pass before files (other than log files) 
        in the Safe can be completely deleted.

    .PARAMETER requestsRetention
        The number of days that must pass before requests can be completely deleted 
        from the Safe.

    .PARAMETER textOnly
        Indicates whether or not the Safe is a text-only Safe.
        
    .PARAMETER securityLevelParm
        The level of the Network Area security flags
        
    .PARAMETER ConfirmationType
        The type of confirmation required to enable access to the Safe. 
        Possible values for this parameter are:
            1 – No confirmation is needed (default)
            2 – Confirmation is needed to open the Safe
            3 – Confirmation is needed to retrieve files
            4 – Confirmation is needed to open the Safe and retrieve files 
                and passwords

        Note: When the value of this parameter is set to ‘0’ (zero), the value of 
        ‘confirmationcount’ will also be set to ‘0’ (zero) automatically instead 
        of to the default value.

    .PARAMETER confirmationCount
        The number of authorized Safe Owners required to confirm the users request to access 
        the Safe. 
        0–64 – The number of authorized Owners that need to confirm (default=1) 
        255 – All authorized Owners need to confirm
        
    .PARAMETER alwaysNeedsConfirmation
        Whether or not all Owners require confirmation to access the Safe.
        
        No – Confirmation is needed only if the request is from an Owner who is unauthorized 
        to confirm requests.
        Yes – All Owners need confirmation, even Owners who are authorized to confirm 
        requests (default). 
        
        Note: This parameter can only be used when working with version 2.50 of the CyberArk 
        Vault.
    
    .PARAMETER safeKeyType
        The type of encryption used to encrypt the contents of the Safe. 
        Possible values are:
            1 – BasicKeyType
            2 – PassKeyType
            3 – FileKeyType
            4 – NoKeyType (during transmission)
    
    .PARAMETER safeKey
        The pathname of the key file used to encrypt the contents of the Safe if the value of 
        ‘safekeytype’ is ‘2’ or ‘3’.
        
    .PARAMETER password
        The password required to encrypt the contents of the Safe if the value of ‘safekeytype’ 
        is ‘2’ or ‘3’.
    
    .PARAMETER keyFilePath
        The pathname of the key required to encrypt the contents of the Safe if the value of 
        ‘safekeytype’ is ‘3’.
        
    .PARAMETER getNewFileAccessMark
        New files will be marked so they can be identified.
        
    .PARAMETER getRetrievedFileAccessMark
        Retrieved files will be marked so they can be identified.
        
    .PARAMETER getModifiedFileAccessMark
        Modified files will be marked so they can be identified.
        
    .PARAMETER readOnlyByDefault
        New owners of this Safe will initially retrieve in readonly access mode.

    .PARAMETER safeOptions
        This parameter enables to Safe to be shared with the following values or 
        combination of them:
        64 – Enable access to partially impersonated users
        128 – Enable access to fully impersonated users
        512 – Enable access to impersonated users with additional Vault authentication
        256 – Enforce Safe opening.
        
        Note: This is combined with a value of 64 in order to allow access to partially 
        impersonated users.
        
    .PARAMETER useFileCategories
        Whether or not to use Vault level file categories when storing a file in a Safe

    .PARAMETER requireReason
        Whether or not a user is required to supply a reason before files and password 
        content can be retrieved from this Safe.
    
    .PARAMETER enforceExclusivePasswords
        Whether or not the Safe will enforce exclusive passwords mode.

    .PARAMETER requireContentValidation
        Whether or not files and passwords in this Safe must be validated before they 
        can be accessed    
        
    .PARAMETER maxFileSize
        The maximum size of files stored in the Safe in KB. 
        The default is ‘0’ which indicates no maximum file size.
        
    .PARAMETER allowedFileTypes
        Indicates which file types are accepted in this Safe.
        
        Possible file types are: 
        DOC, DOT, XLS, XLT, EPS, BMP, GIF, TGA, TIF, TIFF, LOG, TXT, PAL.
        
    .PARAMETER supportOLAC
        Whether or not Object Level Access is supported. 
        The default is ‘No’.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$False)][string]$location,
        [Parameter(Mandatory=$False)][int]$size,
        [Parameter(Mandatory=$False)][string]$description,
        [Parameter(Mandatory=$False)][int]$fromHour,
        [Parameter(Mandatory=$False)][int]$toHour,
        [Parameter(Mandatory=$False)][int]$delay,
        [Parameter(Mandatory=$False)][int]$dailyVersions,
        [Parameter(Mandatory=$False)][int]$monthlyVersions,
        [Parameter(Mandatory=$False)][int]$yearlyVersions,
        [Parameter(Mandatory=$False)][int]$logRetention,
        [Parameter(Mandatory=$False)][int]$fileRetention,
        [Parameter(Mandatory=$False)][int]$requestsRetention,
        #[Parameter(Mandatory=$False)][switch]$virusFree,
        [Parameter(Mandatory=$False)][switch]$textOnly,
        [Parameter(Mandatory=$False)][int]$securityLevelParm,
        [Parameter(Mandatory=$False)][ValidateSet("1","2","3","4")][int]$ConfimrationType,
        [Parameter(Mandatory=$False)]
            [ValidateScript({((($_ -ge 0) -and ($_ -le 64)) -or ($_ -eq 255))})]
                [int]$confirmationCount,
        [Parameter(Mandatory=$False)][switch]$alwaysNeedsConfirmation,
        [Parameter(Mandatory=$False)][ValidateSet("1","2","3","4")][int]$safeKeyType,
        [Parameter(Mandatory=$False)][string]$safeKey,
        [Parameter(Mandatory=$False)][string]$password,
        [Parameter(Mandatory=$False)][string]$keyFilePath,
        [Parameter(Mandatory=$False)][switch]$getNewFileAccessMark,
        [Parameter(Mandatory=$False)][switch]$getRetrievedFileAccessMark,
        [Parameter(Mandatory=$False)][switch]$getModifiedFileAccessMark,
        [Parameter(Mandatory=$False)][switch]$readOnlyByDefault,
        [Parameter(Mandatory=$False)][ValidateSet("64","128","512","256","192","576","320","640","384","768","704","448","832","896","960")][int]$safeOptions,
        [Parameter(Mandatory=$False)][switch]$useFileCategories,
        [Parameter(Mandatory=$False)][switch]$requireReason,
        [Parameter(Mandatory=$False)][switch]$enforceExclusivePasswords,
        [Parameter(Mandatory=$False)][switch]$requireContentValidation,
        [Parameter(Mandatory=$False)][int]$maxFileSize,
        [Parameter(Mandatory=$False)][string]$allowedFileTypes,
        [Parameter(Mandatory=$False)][switch]$supportOLAC,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                        
        [array]$addSafe = (Invoke-Expression "$pacli ADDSAFE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)" -ErrorAction SilentlyContinue) 2>&1
        
        if($LASTEXITCODE){

            write-debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "Error Creating Safe: $safe"
            write-Debug $($addSafe[0]|Out-String)

        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "Safe Created: $safe"


        }
        
    }
    
}

Function Update-Safe{

    <#
    .SYNOPSIS
    	Updates Safe properties

    .DESCRIPTION
    	Exposes the PACLI Function: "UPDATESAFE"

    .PARAMETER vault
        The name of the Vault containing the Safe
        
    .PARAMETER user
        The Username of the User carrying out the task
        
    .PARAMETER safe
        The name of the Safe to update.
        
    .PARAMETER location
        The location of the Safe in the Vault hierarchy.
        Note: Add a backslash ‘\’ before the name of the location.
        
    .PARAMETER size
        The maximum size of the Safe in MB.
        
    .PARAMETER description
        A description of the Safe.
        
    .PARAMETER fromHour
        The time from which Users can access the Safe.
        
    .PARAMETER toHour
        The time until which Users can access the Safe.
        
    .PARAMETER delay
        The delay in seconds between when the User opens the Safe and the Vault 
        permits access

    .PARAMETER dailyVersions
        The number of daily versions of files to be retained.
        
    .PARAMETER monthlyVersions
        The number of monthly versions of files to be retained.
        
    .PARAMETER yearlyVersions
        The number of yearly versions of files to be retained.
        
    .PARAMETER logRetention
        The number of days that must pass before log files can be completely 
        deleted from the Safe.

    .PARAMETER fileRetention
        The number of days that must pass before files (other than log files) 
        in the Safe can be completely deleted.

    .PARAMETER requestsRetention
        The number of days that must pass before requests can be completely deleted 
        from the Safe.

    .PARAMETER safeFilter
        Specifies the type of Safe content filter. 
        Possible values are:
            None – the Safe will be a regular Safe and will not have any content filter.
            TextOnlyFilter – the Safe will only store text files.
            
        Note:
        Text Only Safes can be changed into regular Safes, but a regular Safe cannot become 
        a filtered Safe.

    .PARAMETER safeOptions
        This parameter enables to Safe to be shared with the following values or 
        combination of them:
        64 – Enable access to partially impersonated users
        128 – Enable access to fully impersonated users
        512 – Enable access to impersonated users with additional Vault authentication
        256 – Enforce Safe opening.
        Note: This is combined with a value of 64 in order to allow access to partially 
        impersonated users.
            
    .PARAMETER securityLevelParm
        The level of the Network Area security flags
        
    .PARAMETER ConfimrationType
        The type of confirmation required to enable access to the Safe. 
        Possible values for this parameter are:
            1 – No confirmation is needed (default)
            2 – Confirmation is needed to open the Safe
            3 – Confirmation is needed to retrieve files
            4 – Confirmation is needed to open the Safe and retrieve files 
            and passwords

        Note: When the value of this parameter is set to ‘0’ (zero), the value of 
        ‘confirmationcount’ will also be set to ‘0’ (zero) automatically instead 
        of to the default value.

    .PARAMETER confirmationCount
        The number of authorized Safe Owners required to confirm the users request to access 
        the Safe. 
        0–64 – The number of authorized Owners that need to confirm (default=1) 
        255 – All authorized Owners need to confirm
        
    .PARAMETER alwaysNeedsConfirmation
        Whether or not all Owners require confirmation to access the Safe.
        
        No – Confirmation is needed only if the request is from an Owner who is unauthorized 
        to confirm requests.
        Yes – All Owners need confirmation, even Owners who are authorized to confirm 
        requests (default). 
        
        Note: This parameter can only be used when working with version 2.50 of the CyberArk 
        Vault.

    .PARAMETER getNewFileAccessMark
        New files will be marked so they can be identified.
        
    .PARAMETER getRetrievedFileAccessMark
        Retrieved files will be marked so they can be identified.
        
    .PARAMETER getModifiedFileAccessMark
        Modified files will be marked so they can be identified.
        
    .PARAMETER readOnlyByDefault
        New owners of this Safe will initially retrieve in readonly access mode.

    .PARAMETER useFileCategories
        Whether or not to use Vault level file categories when storing a file in a Safe

    .PARAMETER requireReason
        Whether or not a user is required to supply a reason before files and password 
        content can be retrieved from this Safe.
    
    .PARAMETER enforceExclusivePasswords
        Whether or not the Safe will enforce exclusive passwords mode.

    .PARAMETER requireContentValidation
        Whether or not files and passwords in this Safe must be validated before they 
        can be accessed    
        
    .PARAMETER maxFileSize
        The maximum size of files stored in the Safe in KB. 
        The default is ‘0’ which indicates no maximum file size.
        
    .PARAMETER allowedFileTypes
        Indicates which file types are accepted in this Safe.
        
        Possible file types are: 
        DOC, DOT, XLS, XLT, EPS, BMP, GIF, TGA, TIF, TIFF, LOG, TXT, PAL.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Alias("Name")][Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$False)][string]$location,
        [Parameter(Mandatory=$False)][int]$size,
        [Parameter(Mandatory=$False)][string]$description,
        [Parameter(Mandatory=$False)][int]$fromHour,
        [Parameter(Mandatory=$False)][int]$toHour,
        [Parameter(Mandatory=$False)][int]$delay,
        [Parameter(Mandatory=$False)][int]$dailyVersions,
        [Parameter(Mandatory=$False)][int]$monthlyVersions,
        [Parameter(Mandatory=$False)][int]$yearlyVersions,
        [Parameter(Mandatory=$False)][int]$logRetention,
        [Parameter(Mandatory=$False)][int]$fileRetention,
        [Parameter(Mandatory=$False)][int]$requestRetenion,
        [Parameter(Mandatory=$False)][ValidateSet("None","TextOnlyFilter")][string]$safeFilter,
        [Parameter(Mandatory=$False)]
            [ValidateSet("64","128","512","256","192","576","320","640","384","768","704","448","832","896","960")]
                [int]$safeOptions,
        [Parameter(Mandatory=$False)][int]$securityLevelParm,
        [Parameter(Mandatory=$False)]
            [ValidateSet("1","2","3","4")]
                [int]$confirmationType,
        [Parameter(Mandatory=$False)]
            [ValidateScript({((($_ -ge 0) -and ($_ -le 64)) -or ($_ -eq 255))})]
                [int]$confirmationCount,
        [Parameter(Mandatory=$False)][switch]$alwaysNeedConfirmation,
        [Parameter(Mandatory=$False)][switch]$getNewFileAccessMark,
        [Parameter(Mandatory=$False)][switch]$getRetrievedFileAccessMark,
        [Parameter(Mandatory=$False)][switch]$getModifiedFileAccessMark,
        [Parameter(Mandatory=$False)][switch]$readOnlyByDefault,
        [Parameter(Mandatory=$False)][switch]$useFileCategories,
        [Parameter(Mandatory=$False)][switch]$requireReason,
        [Parameter(Mandatory=$False)][switch]$enforceExclusivePasswords,
        [Parameter(Mandatory=$False)][switch]$requireContentValidation,
        [Parameter(Mandatory=$False)][int]$maxFileSize,
        [Parameter(Mandatory=$False)][string]$allowedFileTypes,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $updateSafe = (Invoke-Expression "$pacli UPDATESAFE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1

        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
    }
    
}

Function Rename-Safe{

    <#
    .SYNOPSIS
    	Renames a Safe

    .DESCRIPTION
    	Exposes the PACLI Function: "RENAMESAFE"

    .PARAMETER vault
        The name of the Vault containing the Safe
        
    .PARAMETER user
        The Username of the User carrying out the task
        
    .PARAMETER safe
        The current name of the Safe.
        
    .PARAMETER newName
        The new name of the Safe.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Alias("Name")][Parameter(Mandatory=$True)]$safe,
        [Parameter(Mandatory=$True)]$newName,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                        
        $renameSafe = (Invoke-Expression "$pacli UPDATESAFE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString -quoteOutput)") 2>&1

        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
    }
    
}

Function Remove-Safe{

    <#
    .SYNOPSIS
    	Delete a Safe. It is only possible to delete a Safe after the version 
        retention period has expired for all files contained in the Safe.
        In order to carry out this command successfully, the Safe must be open.

    .DESCRIPTION
        Exposes the PACLI Function: "DELETESAFE"
        A deleted Safe cannot be recovered, make sure that any files that are stored 
        within it are not required as they will be deleted.
    	A detailed description of the function or script. This keyword can be
    	used only once in each topic.

    .PARAMETER vault
        The name of the Vault containing the Safe to delete.
        
    .PARAMETER user
        The Username of the User carrying out the task
        
    .PARAMETER safe
        The name of the Safe to delete.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                        
        $deleteSafe = (Invoke-Expression "$pacli DELETESAFE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)" -ErrorAction SilentlyContinue 2>&1)

        if($LASTEXITCODE){

            write-debug "LastExitCode: $LASTEXITCODE"
            write-debug $($deleteSafe[0]|Out-String)
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
    }
    
}

Function Add-SafeOwner{

    <#
    .SYNOPSIS
    	Enables Safe Owner authorizations to be given to a User in a
        specified Safe.
        In order to carry out this command successfully, the Safe must be open.

    .DESCRIPTION
    	Exposes the PACLI Function: "ADDOWNER"

    .PARAMETER vault
        The name of the Vault to which the Safe Owner has access.
        
    .PARAMETER user
        The Username of the User carrying out the task
        
    .PARAMETER owner
        The name of the Safe Owner to add to the Safe.
        
    .PARAMETER safe
        The name of the Safe to which to add the Safe Owner.
        
    .PARAMETER readOnlyByDefault
        Whether or not the user’s initial access to the files in the Safe is for 
        read-only format.
        
    .PARAMETER retrieve
        Whether or not the Safe Owner will be able to retrieve files.
        
    .PARAMETER store
        Whether or not the Safe Owner will be able to store files.
        
    .PARAMETER delete
        Whether or not the Safe Owner will be able to delete files.
        
    .PARAMETER administer
        Whether or not the Safe Owner will be able to administer the Safe.
        
    .PARAMETER supervise
        Whether or not the Safe Owner will be able to supervise other Safe Owners 
        and confirm requests by other users to enter specific Safes.
        
    .PARAMETER backup
        Whether or not the Safe Owner will be able to backup the Safe.
        
    .PARAMETER manageOwners
        Whether or not the Safe Owner will be able to manage other Safe Owners.
        
    .PARAMETER accessNoConfirmation
        Whether or not the Safe Owner will be able to access the Safe without 
        requiring confirmation from authorized users.
        
    .PARAMETER validateSafeContent
        Whether or not the Safe Owner will be able to change the validation status 
        of the Safe contents.
        
    .PARAMETER list
        Whether or not the Safe Owner will be able to list Safe contents
        
    .PARAMETER usePassword
        Whether or not the Safe Owner will be able to use the password in the PVWA.
        
    .PARAMETER updateObjectProperties
        Whether or not the Safe Owner will be able to update object properties.
        
    .PARAMETER initiateCPMChange
        Whether or not the Safe Owner will be able to initiate CPM changes for 
        passwords.
        
    .PARAMETER initiateCPMChangeWithManualPassword
        Whether or not the Safe Owner will be able to initiate a CPM change with 
        a manual password.
        
    .PARAMETER createFolder
        Whether or not the Safe Owner will be able to create folders.
        
    .PARAMETER deleteFolder
        Whether or not the Safe Owner will be able to delete folders.
        
    .PARAMETER moveFrom
        Whether or not the Safe Owner will be able to move objects from their 
        existing locations.
        
    .PARAMETER moveInto
        Whether or not the Safe Owner will be able to move objects into new 
        locations.
        
    .PARAMETER viewAudit
        Whether or not the Safe Owner will be able to view other users’ audits.
        
    .PARAMETER viewPermissions
        Whether or not the Safe Owner will be able to view permissions of other 
        users.
        
    .PARAMETER eventsList
        Whether or not the Safe Owner will be able to list events.
        Note: To allow Safe Owners to access the Safe, make sure this is set to YES.
        
    .PARAMETER addEvents
        Whether or not the Safe Owner will be able to add events.
        
    .PARAMETER createObject 
        Whether or not the Safe Owner will be able to create new objects.
        
    .PARAMETER unlockObject
        Whether or not the Safe Owner will be able to unlock objects.
        
    .PARAMETER renameObject
        Whether or not the Safe Owner will be able to rename objects.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$owner,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$False)][switch]$readOnlyByDefault,
        [Parameter(Mandatory=$False)][switch]$retrieve,
        [Parameter(Mandatory=$False)][switch]$store,
        [Parameter(Mandatory=$False)][switch]$delete,
        [Parameter(Mandatory=$False)][switch]$administer,
        [Parameter(Mandatory=$False)][switch]$supervise,
        [Parameter(Mandatory=$False)][switch]$backup,
        [Parameter(Mandatory=$False)][switch]$manageOwners,
        [Parameter(Mandatory=$False)][switch]$accessNoConfirmation,
        [Parameter(Mandatory=$False)][switch]$validateSafeContent,
        [Parameter(Mandatory=$False)][switch]$list,
        [Parameter(Mandatory=$False)][switch]$usePassword,
        [Parameter(Mandatory=$False)][switch]$updateObjectProperties,
        [Parameter(Mandatory=$False)][switch]$initiateCPMChange,
        [Parameter(Mandatory=$False)][switch]$initiateCPMChangeWithManualPassword,
        [Parameter(Mandatory=$False)][switch]$createFolder,
        [Parameter(Mandatory=$False)][switch]$deleteFolder,
        [Parameter(Mandatory=$False)][switch]$moveFrom,
        [Parameter(Mandatory=$False)][switch]$moveInto,
        [Parameter(Mandatory=$False)][switch]$viewAudit,
        [Parameter(Mandatory=$False)][switch]$viewPermissions,
        [Parameter(Mandatory=$False)][switch]$eventsList,
        [Parameter(Mandatory=$False)][switch]$addEvents,
        [Parameter(Mandatory=$False)][switch]$createObject,
        [Parameter(Mandatory=$False)][switch]$unlockObject,
        [Parameter(Mandatory=$False)][switch]$renameObject,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                        
        $safeOwner = (Invoke-Expression "$pacli ADDOWNER $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString )") 2>&1

        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            write-verbose "Error Adding Safe Owner: $owner"
            write-Debug $($safeOwner|Out-String)
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            write-verbose "Added Safe Owner: $owner"
            
        }
        
    }
    
}

Function Update-SafeOwner{

    <#
    .SYNOPSIS
    	Updates the Safe Owner authorizations of a particular Safe Owner.
        In order to carry out this command successfully, the Safe must be open.

    .DESCRIPTION
    	Exposes the PACLI Function: "UPDATEOWNER"

    .PARAMETER vault
        The name of the Vault to which the Safe Owner has access.
        
    .PARAMETER user
        The Username of the User carrying out the task
        
    .PARAMETER owner
        The name of the Safe Owner whose authorizations will be updated
        
    .PARAMETER safe
        The name of the Safe in which the Safe Owner's authorizations apply.
        
    .PARAMETER readOnlyByDefault
        Whether or not the user’s initial access to the files in the Safe is for 
        read-only format.
        
    .PARAMETER retrieve
        Whether or not the Safe Owner will be able to retrieve files.
        
    .PARAMETER store
        Whether or not the Safe Owner will be able to store files.
        
    .PARAMETER delete
        Whether or not the Safe Owner will be able to delete files.
        
    .PARAMETER administer
        Whether or not the Safe Owner will be able to administer the Safe.
        
    .PARAMETER supervise
        Whether or not the Safe Owner will be able to supervise other Safe Owners 
        and confirm requests by other users to enter specific Safes.
        
    .PARAMETER backup
        Whether or not the Safe Owner will be able to backup the Safe.
        
    .PARAMETER manageOwners
        Whether or not the Safe Owner will be able to manage other Safe Owners.
        
    .PARAMETER accessNoConfirmation
        Whether or not the Safe Owner will be able to access the Safe without 
        requiring confirmation from authorized users.
        
    .PARAMETER validateSafeContent
        Whether or not the Safe Owner will be able to change the validation status 
        of the Safe contents.
        
    .PARAMETER list
        Whether or not the Safe Owner will be able to list Safe contents
        
    .PARAMETER usePassword
        Whether or not the Safe Owner will be able to use the password in the PVWA.
        
    .PARAMETER updateObjectProperties
        Whether or not the Safe Owner will be able to update object properties.
        
    .PARAMETER initiateCPMChange
        Whether or not the Safe Owner will be able to initiate CPM changes for 
        passwords.
        
    .PARAMETER initiateCPMChangeWithManualPassword
        Whether or not the Safe Owner will be able to initiate a CPM change with 
        a manual password.
        
    .PARAMETER createFolder
        Whether or not the Safe Owner will be able to create folders.
        
    .PARAMETER deleteFolder
        Whether or not the Safe Owner will be able to delete folders.
        
    .PARAMETER moveFrom
        Whether or not the Safe Owner will be able to move objects from their 
        existing locations.
        
    .PARAMETER moveInto
        Whether or not the Safe Owner will be able to move objects into new 
        locations.
        
    .PARAMETER viewAudit
        Whether or not the Safe Owner will be able to view other users’ audits.
        
    .PARAMETER viewPermissions
        Whether or not the Safe Owner will be able to view permissions of other 
        users.
        
    .PARAMETER eventsList
        Whether or not the Safe Owner will be able to list events.
        Note: To allow Safe Owners to access the Safe, make sure this is set to YES.
        
    .PARAMETER addEvents
        Whether or not the Safe Owner will be able to add events.
        
    .PARAMETER createObject 
        Whether or not the Safe Owner will be able to create new objects.
        
    .PARAMETER unlockObject
        Whether or not the Safe Owner will be able to unlock objects.
        
    .PARAMETER renameObject
        Whether or not the Safe Owner will be able to rename objects.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][String]$owner,
        [Parameter(Mandatory=$True)][String]$safe,
        [Parameter(Mandatory=$False)][Switch]$readOnlyByDefault,
        [Parameter(Mandatory=$False)][Switch]$retrieve,
        [Parameter(Mandatory=$False)][Switch]$store,
        [Parameter(Mandatory=$False)][Switch]$delete,
        [Parameter(Mandatory=$False)][Switch]$administer,
        [Parameter(Mandatory=$False)][Switch]$supervise,
        [Parameter(Mandatory=$False)][Switch]$backup,
        [Parameter(Mandatory=$False)][Switch]$manageOwners,
        [Parameter(Mandatory=$False)][Switch]$accessNoConfirmation,
        [Parameter(Mandatory=$False)][Switch]$validateSafeContent,
        [Parameter(Mandatory=$False)][Switch]$list,
        [Parameter(Mandatory=$False)][Switch]$usePassword,
        [Parameter(Mandatory=$False)][Switch]$updateObjectProperties,
        [Parameter(Mandatory=$False)][Switch]$initiateCPMChange,
        [Parameter(Mandatory=$False)][Switch]$initiateCPMChangeWithManualPassword,
        [Parameter(Mandatory=$False)][Switch]$createFolder,
        [Parameter(Mandatory=$False)][Switch]$deleteFolder,
        [Parameter(Mandatory=$False)][Switch]$moveFrom,
        [Parameter(Mandatory=$False)][Switch]$moveInto,
        [Parameter(Mandatory=$False)][Switch]$viewAudit,
        [Parameter(Mandatory=$False)][Switch]$viewPermissions,
        [Parameter(Mandatory=$False)][Switch]$eventsList,
        [Parameter(Mandatory=$False)][Switch]$addEvents,
        [Parameter(Mandatory=$False)][Switch]$createObject,
        [Parameter(Mandatory=$False)][Switch]$unlockObject,
        [Parameter(Mandatory=$False)][Switch]$renameObject,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                        
        $updateOwner = (Invoke-Expression "$pacli UPDATEOWNER $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
    }
    
}

Function Remove-SafeOwner{

    <#
    .SYNOPSIS
    	Deletes a Safe Owner, thus removing their permissions and authority to 
        enter the Safe.
        In order to carry out this command successfully, the Safe must be open.

    .DESCRIPTION
    	Exposes the PACLI Function: "DELETEOWNER"

    .PARAMETER vault
        The name of the Vault to which the Safe Owner has access.
        
    .PARAMETER user
        The Username of the User carrying out the task
        
    .PARAMETER owner
        The name of the Safe Owner to remove from the Vault.
        
    .PARAMETER safe
        The name of the Safe from which to remove the Safe Owner.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][String]$safe,
        [Parameter(Mandatory=$True)][String]$owner,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $deleteOwner = (Invoke-Expression "$pacli DELETEOWNER $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1

        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"


        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"


        }
        
    }
    
}

Function Get-OwnerSafes{

    <#
    .SYNOPSIS
    	Lists of the Safes to which the specified Safe Owner has ownership.

    .DESCRIPTION
    	Exposes the PACLI Function: "OWNERSAFESLIST"

    .PARAMETER vault
        The name of the Vault to which the Safe Owner has access.
        
    .PARAMETER user
        The Username of the User carrying out the task
        
    .PARAMETER owner
        The name of the Safe Owner.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][String]$owner,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                        
        #execute pacli
        $ownerSafesList = Invoke-Expression "$pacli OWNERSAFESLIST $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
            
            #ignore whitespace
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"

            If($ownerSafesList){
            
                ForEach($ownerSafe in $ownerSafesList){
        
                    write-debug $ownerSafe
                    
                    #define hash to hold values
                    $ownerSafes = @{}
                    
                    $values = $ownerSafe | ConvertFrom-PacliOutput
                    
                    #Add array elements to hashtable
                    $ownerSafes.Add("Name",$values[0])
                    $ownerSafes.Add("AccessLevel",$values[1])
                    $ownerSafes.Add("ExpirationDate",$values[2])

                    #return object from hashtable
                    New-Object -TypeName psobject -Property $ownerSafes | 
                        
                        select Name, AccessLevel, ExpirationDate 
                        
                }
            
            }
            
        }
        
    }
    
}

Function Get-SafeDetails{

    <#
    .SYNOPSIS
    	Lists Safe details
        
    .DESCRIPTION
    	Exposes the PACLI Function: "SAFEDETAILS"

    .PARAMETER vault
        The name of the Vault to which the Safe Owner has access.
        
    .PARAMETER user
        The Username of the User carrying out the task
        
    .PARAMETER safe
        The name of the Safe whose details will be listed.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][String]$safe,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                        
        #define hash to hold values
        $details = @{}
        
        #execute pacli
        $safeDetails = Invoke-Expression "$pacli SAFEDETAILS $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE,OEM)'" | 
            
            #ignore whitespaces, return string
            Select-String -Pattern "\S" | Out-String
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
            If($safeDetails){
            
                Write-Debug $safeDetails
        
                $values = $safeDetails | ConvertFrom-PacliOutput
                
                #Add elements to hashtable
                $details.Add("Description",$values[0])
                $details.Add("Delay",$values[1])
                $details.Add("Retention",$values[2])
                $details.Add("ObjectsRetention",$values[3])
                $details.Add("MaxSize",$values[4])
                $details.Add("CurrSize",$values[5])
                $details.Add("FromHour",$values[6])
                $details.Add("ToHour",$values[7])
                $details.Add("DailyVersions",$values[8])
                $details.Add("MonthlyVersions",$values[9])
                $details.Add("YearlyVersions",$values[10])
                $details.Add("QuotaOwner",$values[11])
                $details.Add("Location",$values[12])
                $details.Add("RequestsRetention",$values[13])
                $details.Add("ConfirmationType",$values[14])
                $details.Add("SecurityLevel",$values[15])
                $details.Add("DefaultAccessMarks",$values[16])
                $details.Add("ReadOnlyByDefault",$values[17])
                $details.Add("UseFileCategories",$values[18])
                $details.Add("VirusFree",$values[19])
                $details.Add("TextOnly",$values[20])
                $details.Add("RequireReason",$values[21])
                $details.Add("EnforceExclusivePasswords",$values[22])
                $details.Add("RequireContentValidation",$values[23])
                $details.Add("ShareOptions",$values[24])
                $details.Add("ConfirmationCount",$values[25])
                $details.Add("MaxFileSize",$values[26])
                $details.Add("AllowedFileTypes",$values[27])
                $details.Add("SupportOLAC",$values[28])

                #return object from hashtable
                New-Object -TypeName psobject -Property $details | select Description, Delay, Retention, ObjectsRetention, 
                    MaxSize, CurrSize, FromHour, ToHour, DailyVersions, MonthlyVersions, YearlyVersions, QuotaOwner,
                        Location, RequestsRetention, ConfirmationType, SecurityLevel, DefaultAccessMarks, ReadOnlyByDefault,
                            UseFileCategories, VirusFree, TextOnly, RequireReason, EnforceExclusivePasswords, 
                                RequireContentValidation, ShareOptions, ConfirmationCount, MaxFileSize, AllowedFileTypes, 
                                    SupportOLAC
            
            }
            
        }
        
    }
            
}

Function Get-Safe{

    <#
    .SYNOPSIS
    	Produces a list of Safes in the specified Vault

    .DESCRIPTION
    	Exposes the PACLI Function: "SAFESLIST
        
    .PARAMETER vault
        The name of the Vault containing the Safes to list.
        
    .PARAMETER user
        The Username of the User who is logged on.

    .PARAMETER location
        The location to search in for the Safes to include in the list.
        Note: Add a backslash ‘\’ before the name of the location.

    .PARAMETER includeSubLocations
        Whether or not in include sublocation(s) of the specified location in 
        the list.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$False)][string]$location,
        [Parameter(Mandatory=$False)][switch]$includeSubLocations,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                            
        #execute pacli
        $safesList = Invoke-Expression "$pacli SAFESLIST $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
            
            #ignore whitespace
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            if($safesList){
                
                foreach($safe in $safesList){
                    
                    #define hash to hold values
                    $vaultSafe = @{}
                    
                    #remove line break characters in data, 
                    $values = $safe | ConvertFrom-PacliOutput
                
                    #write-debug $values.count
                        
                    #assign values to properties
                    $vaultSafe.Add("Name",$values[0])
                    $vaultSafe.Add("Size",$values[1])
                    $vaultSafe.Add("Status",$values[2])
                    $vaultSafe.Add("LastUsed",$values[3])
                    $vaultSafe.Add("Accessed",$values[4])
                    $vaultSafe.Add("VirusFree",$values[5])
                    $vaultSafe.Add("ShareOptions",$values[6])
                    $vaultSafe.Add("Location",$values[7])
                    $vaultSafe.Add("UseFileCategories",$values[8])
                    $vaultSafe.Add("TextOnly",$values[9])
                    $vaultSafe.Add("RequireReason",$values[10])
                    $vaultSafe.Add("EnforceExclusivePasswords",$values[11])
                    $vaultSafe.Add("RequireContentValidation",$values[12])
                    $vaultSafe.Add("AccessLevel",$values[13])
                    $vaultSafe.Add("MaxSize",$values[14])
                    $vaultSafe.Add("ReadOnlyByDefault",$values[15])
                    $vaultSafe.Add("SafeID",$values[16])
                    $vaultSafe.Add("LocationID",$values[17])
                    $vaultSafe.Add("SupportOLAC",$values[18])
                    
                    #output object
                    new-object -Type psobject -Property $vaultSafe | select Name, Size, Status, LastUsed, Accessed, VirusFree,
                        ShareOptions, Location, UseFileCategories, TextOnly, RequireReason, EnforceExclusivePasswords,
                            RequireContentValidation, AccessLevel, MaxSize, ReadOnlyByDefault, SafeID, LocationID, SupportOLAC
                
                }
                
            }
            
        }
        
    }

}

Function Get-SafeOwners{

    <#
    .SYNOPSIS
    	Produces a list of all the Safe Owners of the specified Safe(s).

    .DESCRIPTION
    	Exposes the PACLI Function: "OWNERSLIST"

    .PARAMETER vault
        The name of the Vault containing the specified Safe.
        
    .PARAMETER user
        The Username of the User who is logged on.
        
    .PARAMETER safePattern
        The full name or part of the name of the Safe(s) to include in the list. 
        Alternatively, a wildcard can be used in this parameter.
        
    .PARAMETER ownerPattern
        The full name or part of the name of the Owner(s) to include in the list. 
        Alternatively, a wildcard can be used in this parameter.
        
    .PARAMETER includeGroupMembers
        Whether or not to include individual members of Groups in the list.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safePattern,
        [Parameter(Mandatory=$True)][string]$ownerPattern,
        [Parameter(Mandatory=$False)][switch]$includeGroupMembers,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                            
        #execute pacli    
        $ownersList = Invoke-Expression "$pacli OWNERSLIST $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
        
            #ignore whitespace
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
            If($ownersList){
            
                ForEach($owner in $ownersList){
        
                    #define hash to hold values
                    $owners = @{}
                    
                    $values = $owner | ConvertFrom-PacliOutput
                    
                    #Add elements to hashtable
                    $owners.Add("Name",$values[0])
                    $owners.Add("Group",$values[1])
                    $owners.Add("SafeName",$values[2])
                    $owners.Add("AccessLevel",$values[3])
                    $owners.Add("OpenDate",$values[4])
                    $owners.Add("OpenState",$values[5])
                    $owners.Add("ExpirationDate",$values[6])
                    $owners.Add("GatewayAccount",$values[7])
                    $owners.Add("ReadOnlyByDefault",$values[8])
                    $owners.Add("SafeID",$values[9])
                    $owners.Add("UserID",$values[10])

                    #return object from hashtable
                    New-Object -TypeName psobject -Property $owners | select Name, Group, SafeName, AccessLevel, OpenDate, 
                        OpenState, ExpirationDate, GatewayAccount, ReadOnlyByDefault, SafeID, UserID
                        
                }
            
            }
            
        }
        
    }
    
}

Function Get-SafeActivity{

    <#
    .SYNOPSIS
    	Produces a list of activities of all the Safe Owners of the specified
        Safe(s).

    .DESCRIPTION
    	Exposes the PACLI Function: "INSPECTSAFE"

    .PARAMETER vault
        The name of the Vault containing the specified Safe.
        
    .PARAMETER user
        The Username of the User carrying out the task.
        
    .PARAMETER safePattern
        The full name or part of the name of the Safe(s) to include in the report. 
        Alternatively, a wildcard can be used in this parameter.
        The default is ‘*’ (wildcard).
        
    .PARAMETER userPattern
        The full name or part of the name of the Owner(s) to include in the list. 
        Alternatively, a wildcard can be used in this parameter.
        
    .PARAMETER logdays
        The number of days to include in the list of activities.
        The default is ‘-1’, meaning that all the days registered in the log will be included.

    .PARAMETER alertsOnly
        Whether or not the activities list will contain only alerts or every activity.
        The default is ‘NO’.

    .PARAMETER fileName
        The full path name of the file where the log records will be saved.

    .PARAMETER codes
        The message codes that will be used to filter the log activities. 
        Multiple codes are separated by commas.

    .PARAMETER fromDate
        The first day to be included in the list of activities. 
        Use the following date format: dd/mm/yyyy.

    .PARAMETER toDate
        The last day to be included in the list of activities. 
        Use the following date format: dd/mm/yyyy.

    .PARAMETER requestID
        The unique ID of a request in the list of activities.

    .PARAMETER categoriesNames
        The name of the categories to include in the list. 
        
        Separate multiple category names with the value of the 
        CATEGORIESSEPERATOR parameter. 
        
        Specify a corresponding value for each category name in the 
        CATEGORIESVALUE parameter.

    .PARAMETER categoriesValues
        The value of each category specified in the CATEGORIESNAMES parameter. 
        
        Separate multiple category names with the value of the 
        CATEGORIESSEPERATOR parameter. 
        
        Specify a corresponding value for each category in the 
        CATEGORIESNAME parameter.

    .PARAMETER categoriesSeperator
        The separator between multiple category names and multiple category values.
        The default is ‘,’ (comma).

    .PARAMETER categoryFilterType
        The type of category filter. Possible values are:
            AND – Categories will be filtered according to all the 
                specified filters.
            OR – Categories will be filtered according to one of the 
                specified categories.
                The default is ‘AND’.

    .PARAMETER maxRecords
        The maximum number of records to retrieve.

    .PARAMETER userType
        The user type to use to filter activities.

    .PARAMETER options
        The INSPECTSAFE options. 
        Possible values are:
            1 – Returns the results in descending order.
            2 – Indicates the user pattern is in regular expression.
            4 – Uses negation for user pattern regular expression.
            16 – Displays only an external audit.
            32 – Displays only an internal audit.
            64 – Sort according to external time.
            128 – The user pattern is the exact string, not a wildcard 
                or regular expression.
            256 – Shows system audit.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safePattern,
        [Parameter(Mandatory=$True)][string]$userPattern,
        [Parameter(Mandatory=$False)][int]$logdays,
        [Parameter(Mandatory=$False)][switch]$alertsOnly,
        [Parameter(Mandatory=$False)][string]$fileName,
        [Parameter(Mandatory=$False)][string]$codes,
        [Parameter(Mandatory=$False)]
            [ValidateScript({($_ -eq (get-date $_ -f dd/MM/yyyy))})]
                [string]$fromDate,
        [Parameter(Mandatory=$False)]
            [ValidateScript({($_ -eq (get-date $_ -f dd/MM/yyyy))})]
                [string]$toDate,
        [Parameter(Mandatory=$False)][string]$requestID,
        [Parameter(Mandatory=$False)][string]$categoriesNames,
        [Parameter(Mandatory=$False)][string]$categoriesValues,
        [Parameter(Mandatory=$False)][string]$categoriesSeperator,
        [Parameter(Mandatory=$False)][ValidateSet("OR","AND")][string]$categoryFilterType,
        [Parameter(Mandatory=$False)][int]$maxRecords,
        [Parameter(Mandatory=$False)][string]$userType,
        [Parameter(Mandatory=$False)][ValidateSet("1","2","4","16","32","64","128","256")][int]$options,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                        
        #execute pacli    
        $getSafeActivity = Invoke-Expression "$pacli INSPECTSAFE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
        
            #ignore whitespace
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
            If($safeActivity){
            
                ForEach($activity in $getSafeActivity){
        
                    #define hash to hold values
                    $safeActivity = @{}
                    
                    $values = $activity | ConvertFrom-PacliOutput
                    
                    #Add elements to hashtable
                    $safeActivity.Add("Time",$values[0])
                    $safeActivity.Add("User",$values[1])
                    $safeActivity.Add("Safe",$values[2])
                    $safeActivity.Add("Activity",$values[3])
                    $safeActivity.Add("Location",$values[4])
                    $safeActivity.Add("NewLocation",$values[5])
                    $safeActivity.Add("RequestID",$values[6])
                    $safeActivity.Add("RequestReason",$values[7])
                    $safeActivity.Add("Code",$values[8])

                    #return object from hashtable
                    New-Object -TypeName psobject -Property $safeActivity | select Time, User, Safe, Activity, Location, 
                        NewLocation, RequestID, RequestReason, Code
                        
                }
            
            }
            
        }
        
    }
    
}

Function Add-SafeFileCategory{

    <#
    .SYNOPSIS
    	Adds File Categories at Safe level

    .DESCRIPTION
    	Exposes the PACLI Function: "ADDSAFEFILECATEGORY"

    .PARAMETER vault
        The name of the Vault containing the Safe where the File Category will 
        be added.
        
    .PARAMETER user
        The Username of the User carrying out the task.
        
    .PARAMETER safe
        The Safe where the File Category will be added.
        
    .PARAMETER category
        The name of the File Category.
        
    .PARAMETER type
        The type of File Category. 
        Valid values for this parameter are:
            cat_text – a textual value
            cat_numeric – a numeric value
            cat_list – a list value
            
    .PARAMETER validValues
        The valid values for the File Category.

    .PARAMETER defaultValue
        The default value for the File Category.
        
    .PARAMETER required
        Whether or not the File Category is a requirement when storing a file in 
        the Safe.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$False)][String]$safe,
        [Parameter(Mandatory=$True)][string]$category,
        [Parameter(Mandatory=$False)][ValidateSet("cat_text","cat_numeric","cat_list")][String]$type,
        [Parameter(Mandatory=$False)][String]$validValues,
        [Parameter(Mandatory=$False)][String]$defaultValue,
        [Parameter(Mandatory=$False)][Switch]$required,
        [Parameter(Mandatory=$False)][int]$sessionID
    )


    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $addSafeFileCategory = (Invoke-Expression "$pacli ADDSAFEFILECATEGORY $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
    }
    
}

Function Update-SafeFileCategory{

    <#
    .SYNOPSIS
    	Update an existing File Category at Safe level

    .DESCRIPTION
    	Exposes the PACLI Function: "UPDATESAFEFILECATEGORY"

    .PARAMETER vault
        The name of the Vault containing the Safe where the File Category is 
        defined.
        
    .PARAMETER user
        The Username of the User carrying out the task.
        
    .PARAMETER safe
        The Safe where the File Categories will be updated.
        
    .PARAMETER category
        The current name of the File Category.

    .PARAMETER categoryNewName
        The new name of the File Category.

    .PARAMETER validValues
        The valid values for the File Category.

    .PARAMETER defaultValue
        The default value for the File Category.
        
    .PARAMETER required
        Whether or not the File Category is a requirement when storing a file in 
        the Safe.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$False)][String]$safe,
        [Parameter(Mandatory=$True)][string]$category,
        [Parameter(Mandatory=$False)][String]$categoryNewName,
        [Parameter(Mandatory=$False)][String]$validValues,
        [Parameter(Mandatory=$False)][String]$defaultValue,
        [Parameter(Mandatory=$False)][Switch]$required,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $updateSafeFileCategory = (Invoke-Expression "$pacli UPDATESAFEFILECATEGORY $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
    }
    
}

Function Remove-SafeFileCategory{

    <#
    .SYNOPSIS
    	Deletes a File Category at Safe level.

    .DESCRIPTION
    	Exposes the PACLI Function: "DELETESAFEFILECATEGORY"

    .PARAMETER vault
        The name of the Vault containing the Safe where the File Category is 
        defined.
        
    .PARAMETER user
        The Username of the User carrying out the task.
        
    .PARAMETER safe
        The Safe where the File Categories is defined.
        
    .PARAMETER category
        The name of the File Category to delete.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$False)][String]$safe,
        [Parameter(Mandatory=$True)][string]$category,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $removeSafeFileCategory = (Invoke-Expression "$pacli DELETESAFEFILECATEGORY $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
    }
    
}

Function Get-SafeFileCategory{

    <#
    .SYNOPSIS
    	Lists all the File Categories that are available in the specified Safe

    .DESCRIPTION
    	Exposes the PACLI Function: "LISTSAFEFILECATEGORIES"

    .PARAMETER vault
        The name of the Vault containing the Safe where the File Category is 
        defined.
        
    .PARAMETER user
        The Username of the User carrying out the task.
        
    .PARAMETER safe
        The Safe where the File Categories is defined.
        
    .PARAMETER category
        The name of the File Category to list.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$False)][string]$safe,
        [Parameter(Mandatory=$False)][string]$category,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        #execute pacli    
        $categoriesList = Invoke-Expression "$pacli LISTSAFEFILECATEGORIES $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
        
            #ignore whitespace
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
            If($categoriesList){
            
                ForEach($category in $categoriesList){
        
                    #define hash to hold values
                    $categoryList = @{}
                    
                    $values = $category | ConvertFrom-PacliOutput
                    
                    #Add elements to hashtable
                    $categoryList.Add("CategoryID",$values[0])
                    $categoryList.Add("CategoryName",$values[1])
                    $categoryList.Add("CategoryType",$values[2])
                    $categoryList.Add("CategoryValidValues",$values[3])
                    $categoryList.Add("CategoryDefaultValue",$values[4])
                    $categoryList.Add("CategoryRequired",$values[5])
                    $categoryList.Add("VaultCategory",$values[6])

                    #return object from hashtable
                    New-Object -TypeName psobject -Property $categoryList | select CategoryID, CategoryName, CategoryType, CategoryValidValues, 
                        CategoryDefaultValue, CategoryRequired, VaultCategory
                        
                }
            
            }
            
        }
        
    }
    
}

Function Add-SafeEvent{

    <#
    .SYNOPSIS
    	Adds a new application Event manually to the current Safe.

    .DESCRIPTION
    	Exposes the PACLI Function: "ADDEVENT"

    .PARAMETER vault
        The name of the Vault where the Event is saved.
        
    .PARAMETER user
        The Username of the User carrying out the task.
        
    .PARAMETER safe
        The name of the Safe where the Event is saved.
                
    .PARAMETER sourceID
        The unique source ID number that represents the application that
        added the Event to the Events log in the Safe.
        
        Note: Before adding your own type of events, contact your
        CyberArk support representative to receive a unique SourceID
        identifier.
    
    .PARAMETER eventTypeID
        A unique ID of the type of Event written to the Events log, specific to
        the application that carried out the event.
    
    .PARAMETER data
        A free text field that specifies details about the Event.
            
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][String]$safe,
        [Parameter(Mandatory=$True)][String]$sourceID,
        [Parameter(Mandatory=$True)][String]$eventTypeID,
        [Parameter(Mandatory=$True)][String]$data,
        [Parameter(Mandatory=$False)][int]$sessionID
    )


    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $addSafeEvent = (Invoke-Expression "$pacli ADDEVENT $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
    }
    
}

Function Get-SafeEvents{

    <#
    .SYNOPSIS
    	Lists Safe Events that are written in the current Safe.

    .DESCRIPTION
    	Exposes the PACLI Function: "SAFEEVENTSLIST"

    .PARAMETER vault
        The name of the Vault that contains the Events.
    
    .PARAMETER user
        The name of the User who is carrying out the task.
    
    .PARAMETER safePatternName
        A Safe name pattern to include in the returned Events list.
    
    .PARAMETER sourceIDList
        A specific source ID for filtering the Events list. If this parameter
        is not specified, all the SourceId’s will be included in the
        returned Events list.
        Note: This parameter has been deprecated.
    
    .PARAMETER eventTypeIDList
        An Event type ID for filtering the Events list. If this parameter is
        not specified, all the EventTypeId’s will be included in the
        returned Events list.
    
    .PARAMETER fromDate
        The first date to include in the returned Events list.
    
    .PARAMETER dataSubstring
        The string that is included in the Data field of the Event that will
        be included in the returned Events list.
    
    .PARAMETER numOfEvents
        The number of recent Events to include in the returned Events list.
    
    .PARAMETER caseSensitive
        Whether or not the filter according to the ‘datasubstring’
        parameter will be case-sensitive.
    
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$False)][string]$safePatternName,
        [Parameter(Mandatory=$False)][string]$sourceIDList,
        [Parameter(Mandatory=$False)][string]$eventTypeIDList,
        [Parameter(Mandatory=$False)]
            [ValidateScript({($_ -eq (get-date $_ -f dd/MM/yyyy))})]
                [string]$fromDate,
        [Parameter(Mandatory=$False)][string]$dataSubstring,
        [Parameter(Mandatory=$False)][int]$numOfEvents,
        [Parameter(Mandatory=$False)][switch]$caseSensitive,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                        
        #execute pacli    
        $safeEventsList = Invoke-Expression "$pacli SAFEEVENTSLIST $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
        
            #ignore whitespace
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
            If($safeEventsList){
            
                ForEach($event in $safeEventsList){
        
                    #define hash to hold values
                    $eventList = @{}
                    
                    $values = $event | ConvertFrom-PacliOutput
                    
                    #Add elements to hashtable
                    $eventList.Add("SafeName",$values[0])
                    $eventList.Add("SafeID",$values[1])
                    $eventList.Add("EventID",$values[2])
                    $eventList.Add("SourceID",$values[3])
                    $eventList.Add("EventTypeID",$values[4])
                    $eventList.Add("CreationDate",$values[5])
                    $eventList.Add("ExpirationDate",$values[6])
                    $eventList.Add("UserName",$values[7])
                    $eventList.Add("UserID",$values[8])
                    $eventList.Add("AgentName",$values[9])
                    $eventList.Add("AgentID",$values[10])
                    $eventList.Add("ClientID",$values[11])
                    $eventList.Add("Version",$values[12])
                    $eventList.Add("FromIP",$values[13])
                    $eventList.Add("Data",$values[14])
                    
                    #return object from hashtable
                    New-Object -TypeName psobject -Property $eventList | select SafeName, SafeID, EventID, SourceID, 
                        EventTypeID, CreationDate, ExpirationDate, UserName, UserID, AgentName, AgentID, ClientID,
                            Version, FromIP, Data
                        
                }
            
            }
            
        }
        
    }
    
}

Function Add-SafeNote{

    <#
    .SYNOPSIS
    	Adds a note to the specified Safe

    .DESCRIPTION
    	Exposes the PACLI Function: "ADDNOTE"

    .PARAMETER vault
        The name of the Vault containing the Safe to which to add a note.
    
    .PARAMETER user
        The Username of the User carrying out the task.
    
    .PARAMETER safe
        The Safe to which to add a note.
    
    .PARAMETER subject
        The subject title of the note.
    
    .PARAMETER text
        The content of the note.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][String]$safe,
        [Parameter(Mandatory=$False)][String]$subject,
        [Parameter(Mandatory=$False)][String]$text,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $addSafeNote = (Invoke-Expression "$pacli ADDNOTE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
    }
    
}

Function Reset-Safe{

    <#
    .SYNOPSIS
    	Resets the access marks on an open Safe.

    .DESCRIPTION
    	Exposes the PACLI Function: "RESETSAFE"

    .PARAMETER vault
        The name of the Vault to reset.
    
    .PARAMETER user
        The Username of the User who is logged on.
    
    .PARAMETER safe
        The name of the Safe containing the access marks to reset.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][String]$safe,
        [Parameter(Mandatory=$False)][int]$sessionID
    )


    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $resetSafe = (Invoke-Expression "$pacli RESETSAFE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
    }
    
}

Function Clear-SafeHistory{

    <#
    .SYNOPSIS
    	Clears the history of all activity in the specified open Safe.

    .DESCRIPTION
    	Exposes the PACLI Function: "CLEARSAFEHISTORY"

    .PARAMETER vault
        The name of the Vault containing the appropriate Safe.
    
    .PARAMETER user
        The Username of the User who is carrying out the command.
    
    .PARAMETER safe
        The name of the Safe to clear.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][String]$safe,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $resetSafe = (Invoke-Expression "$pacli CLEARSAFEHISTORY $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
    }
    
}

###Folder and File Functions###

Function Add-Folder{

    <#
    .SYNOPSIS
    	Adds a folder to the specified Safe.

    .DESCRIPTION
    	Exposes the PACLI Function: "ADDFOLDER"

    .PARAMETER vault
        The name of the Vault to which to add a folder.

    .PARAMETER user
        The Username of the User who is carrying out the task.

    .PARAMETER safe
        The name of the Safe to which to add the folder.

    .PARAMETER folder
        The name of the new folder.
    
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $addFolder = (Invoke-Expression "$pacli ADDFOLDER $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Remove-Folder{

    <#
    .SYNOPSIS
    	Deletes a folder from an open Safe. A folder can only be deleted if the 
        Safe History retention period has expired for all activity in the folder.

    .DESCRIPTION
    	Exposes the PACLI Function: "DELETEFOLDER"

    .PARAMETER vault
        The name of the Vault containing the appropriate Safe.

    .PARAMETER user
        The Username of the User who is carrying out the task.

    .PARAMETER safe
        The name of the Safe in which the folder will be deleted.

    .PARAMETER folder
        The name of the folder to delete.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $removeFolder = (Invoke-Expression "$pacli DELETEFOLDER $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Restore-Folder{

    <#
    .SYNOPSIS
    	Undeletes a deleted folder in a Safe. A folder can only be undeleted if 
        the Safe History retention period has not expired for all activity in 
        the folder.

    .DESCRIPTION
    	Exposes the PACLI Function: "UNDELETEFOLDER"

    .PARAMETER vault
        The name of the Vault .

    .PARAMETER user
        The Username of the User who is carrying out the task.

    .PARAMETER safe
        The name of the Safe in which the folder will be undeleted.

    .PARAMETER folder
        The name of the folder to undelete.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $restoreFolder = (Invoke-Expression "$pacli UNDELETEFOLDER $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Move-Folder{

    <#
    .SYNOPSIS
    	Moves a folder to a different location within the same Safe.

    .DESCRIPTION
    	Exposes the PACLI Function: "MOVEFOLDER"

    .PARAMETER vault
        The name of the Vault in which the folder is located.

    .PARAMETER user
        The Username of the User who is carrying out the task.

    .PARAMETER safe
        The name of the Safe containing the folder to move.

    .PARAMETER folder
        The name of the folder.

    .PARAMETER newLocation
        The new location of the folder.
        Note: Add a backslash ‘\’ before the name of the location.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$True)][string]$newLocation,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $moveFolder = (Invoke-Expression "$pacli MOVEFOLDER $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Get-Folder{

    <#
    .SYNOPSIS
    	Lists folders in the specified Safe.

    .DESCRIPTION
    	Exposes the PACLI Function: "FOLDERSLIST"

    .PARAMETER vault
        The name of the Vault containing the specified Safe.

    .PARAMETER user
        The Username of the User carrying out the task.

    .PARAMETER safe
        The name of the Safe whose folders will be listed.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                        
        #execute pacli    
        $getFolder = Invoke-Expression "$pacli FOLDERSLIST $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
        
            #ignore whitespace
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
            If($getFolder){
            
                ForEach($folder in $getFolder){
        
                    #define hash to hold values
                    $folderList = @{}
                    
                    $values = $folder | ConvertFrom-PacliOutput
                    
                    #Add elements to hashtable
                    $folderList.Add("Name",$values[0])
                    $folderList.Add("Accessed",$values[1])
                    $folderList.Add("History",$values[2])
                    $folderList.Add("DeletionDate",$values[3])
                    $folderList.Add("DeletedBy",$values[4])
                    
                    #return object from hashtable
                    New-Object -TypeName psobject -Property $folderList | select Name, Accessed, History, DeletionDate, DeletedBy
                        
                }
            
            }
            
        }
        
    }
    
}

Function Add-PreferredFolder{

    <#
    .SYNOPSIS
    	Enables specification of a preferred folder in a Safe.

    .DESCRIPTION
    	Exposes the PACLI Function: "ADDPREFERREDFOLDER"

    .PARAMETER vault
        The name of the Vault containing the specified Safe.

    .PARAMETER user
        The Username of the User who is carrying out the task.

    .PARAMETER safe
        The name of the Safe containing the folder to mark.

    .PARAMETER folder
        The name of the folder to mark as a preferred folder.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $addPreferredFolder = (Invoke-Expression "$pacli ADDPREFERREDFOLDER $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Remove-PreferredFolder{

    <#
    .SYNOPSIS
    	Deletes a preferred folder from a Safe.

    .DESCRIPTION
    	Exposes the PACLI Function: "DELETEPREFFEREDFOLDER"

    .PARAMETER vault
        The name of the Vault containing the specified Safe.

    .PARAMETER user
        The Username of the User who is carrying out the task.

    .PARAMETER safe
        The name of the Safe containing the preferred folder.

    .PARAMETER folder
        The name of the preferred folder to delete.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $removePreferredFolder = (Invoke-Expression "$pacli DELETEPREFERREDFOLDER $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Add-File{

    <#
    .SYNOPSIS
    	Stores a file, that is currently on your local computer, in a secure 
        location in a Safe.

    .DESCRIPTION
    	Exposes the PACLI Function: "STOREFILE"

    .PARAMETER vault
        The name of the Vault to which the User has access.

    .PARAMETER user
        The Username of the User who is carrying out the task.

    .PARAMETER safe
        The name of the Safe where the file will be stored.

    .PARAMETER folder
        The folder in the Safe where the file will be stored.

    .PARAMETER file
        The name of the file as it will be stored in the Safe.

    .PARAMETER localFolder
        The location on the User's terminal where the file is currently
        located.

    .PARAMETER localFile
        The name of the file to be stored in the Vault as it is on the User’s
        terminal.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$True)][string]$file,
        [Parameter(Mandatory=$True)][string]$localFolder,
        [Parameter(Mandatory=$True)][string]$localFile,
        [Parameter(Mandatory=$False)][switch]$deleteMacros,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $removeFile = (Invoke-Expression "$pacli STOREFILE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Get-File{

    <#
    .SYNOPSIS
    	Retrieves a file from a Safe, if the appropriate authorizations are held.

    .DESCRIPTION
    	Exposes the PACLI Function: "RETRIEVEFILE"

    .PARAMETER vault
        The name of the Vault to which the User has access.

    .PARAMETER user
        The Username of the User who is carrying out the task.

    .PARAMETER safe
        The name of the Safe containing the file to retrieve.

    .PARAMETER folder
        The folder in which the file is located.

    .PARAMETER file
        The name of the file to retrieve.

    .PARAMETER localFolder
        The location on the User’s terminal into which the file will be
        retrieved.

    .PARAMETER localFile
        The name under which the file will be saved on the User’s
        terminal.

    .PARAMETER lockFile
        Whether or not the file will be locked after it has been
        retrieved.

    .PARAMETER evenIfLocked
        Whether or not the file will be retrieved if the file is locked by
        another user.

    .PARAMETER requestUsageType
        The operation that the user will carry out. 
        Possible options are:
            REQUEST_AND_USE – create and send a request if
                necessary, or use the confirmation if it has been granted
                to open the Safe/file/password.
            CHECK_DON’T_USE – check if a request has been sent
                or, if not, create one and send an error. If a request is
                not needed, carry out the action.
            USE_ONLY – if the request has been confirmed, or if a
                request is not needed, open the Safe/file/password.
        
        Note: In version 4.1, this parameter has no default value and
        is obsolete. However, it can still be used as long as the
        ‘userequest’, ‘sendrequest’ and ‘executerequest’ parameters
        are not specified.

    .PARAMETER requestAccessType
        Whether the request is for a single or multiple access.
        Possible options are:
            SINGLE – for a single access.
            MULTIPLE – for multiple accesses.
            
    .PARAMETER usableFrom
        The proposed date from when the request will be valid.

    .PARAMETER usableTo
        The proposed date until when the request will be valid.
    
    .PARAMETER requestReason
        The reason for the request.
        
    .PARAMETER userRequest
        If a confirmed request exists, it will be used to open the Safe
        and retrieve the specified file.
    
    .PARAMETER sendRequest
        If a request is required to retrieve the selected file, it will be
        sent.
    
    .PARAMETER executeRequest
        If a confirmed request exists or a request is not needed, the
        specified file will be retrieved.
    
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
        
            Comment:
            If the userequest, sendrequest, and executerequest parameters are all 
            set to ‘no’, and a request is needed, the status of the request will 
            be returned as an error.
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$True)][string]$file,
        [Parameter(Mandatory=$True)][string]$localFolder,
        [Parameter(Mandatory=$True)][string]$localFile,
        [Parameter(Mandatory=$False)][switch]$lockFile,
        [Parameter(Mandatory=$False)][switch]$evenIfLocked,
        [Parameter(Mandatory=$False)][ValidateSet("REQUEST_AND_USE","CHECK_DON’T_USE","USE_ONLY")][string]$requestUsageType,        
        [Parameter(Mandatory=$False)][ValidateSet("SINGLE","MULTIPLE")][string]$requestAccessType,
        [Parameter(Mandatory=$False)][string]$usableFrom,
        [Parameter(Mandatory=$False)][string]$usableTo,
        [Parameter(Mandatory=$False)][string]$requestReason,
        [Parameter(Mandatory=$False)][switch]$userRequest,
        [Parameter(Mandatory=$False)][switch]$sendRequest,
        [Parameter(Mandatory=$False)][switch]$executeRequest,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $removeFile = (Invoke-Expression "$pacli RETRIEVEFILE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Remove-File{

    <#
    .SYNOPSIS
    	Deletes a file or password from the specified Safe. As versions of
        the file or password have been stored in the Safe, it can be undeleted 
        at a later time if necessary.

    .DESCRIPTION
    	Exposes the PACLI Function: "DELETEFILE"

    .PARAMETER vault
        The name of the Vault to which the User has access.

    .PARAMETER user
        The Username of the User who is carrying out the task.

    .PARAMETER safe
        The name of the Safe containing the file to delete.

    .PARAMETER folder
        The folder in which the file is located.

    .PARAMETER file
        The name of the file or password to delete.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$True)][string]$file,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $removeFile = (Invoke-Expression "$pacli DELETEFILE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Restore-File{

    <#
    .SYNOPSIS
    	Undelete a file or password that has been previously deleted.

    .DESCRIPTION
    	Exposes the PACLI Function: "UNDELETEFILE"

    .PARAMETER vault
        The name of the Vault in which the file was stored.

    .PARAMETER user
        The Username of the User who is carrying out the task.

    .PARAMETER safe
        The name of the Safe in which the file was stored.

    .PARAMETER folder
        The name of the folder in which the file was stored.

    .PARAMETER file
        The name of the file or password to undelete.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$True)][string]$file,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $restoreFile = (Invoke-Expression "$pacli UNDELETEFILE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Add-PasswordObject{

    <#
    .SYNOPSIS
    	Stores a password object in the specified safe.

    .DESCRIPTION
    	Exposes the PACLI Function: "STOREPASSWORDOBJECT"

    .PARAMETER vault
        The name of the Vault where the password object is stored.

    .PARAMETER user
        The Username of the User who is carrying out the task.

    .PARAMETER safe
        The name of the Safe where the password object is stored

    .PARAMETER folder
        The name of the folder where the password object is stored.

    .PARAMETER file
        The name of the password object.

    .PARAMETER password
        The password being stored in the password object.
    
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$True)][string]$file,
        [Parameter(Mandatory=$True)][string]$password,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $addPassword = (Invoke-Expression "$pacli STOREPASSWORDOBJECT $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        write-debug ($addPassword|out-string)
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            #error storing password, return false

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            #password stored return true

            
        }
        
    }
    
}

Function Get-PasswordObject{

    <#
    .SYNOPSIS
    	Retrieves a password object from the Vault

    .DESCRIPTION
    	Exposes the PACLI Function: "RETRIEVEPASSWORDOBJECT"

    .PARAMETER vault
        The name of the Vault that contains the password object(s)
        you are looking for.

    .PARAMETER user
        The Username of the User carrying out the task.

    .PARAMETER safe
        The name of the Safe that contains the password object(s)
        you are looking for. You can use a wildcard to specify a wider
        range of safenames.

    .PARAMETER folder
        The name of the folder that contains the password object(s) to
        be found.

    .PARAMETER file
        The name of the password object.

    .PARAMETER lockFile
        Whether or not to lock the password object.

    .PARAMETER evenIfLocked
        Whether or not the file will be retrieved if the password object
        is locked by another user.

    .PARAMETER requestUsageType
        The operation that the user will carry out. 
        Possible options are:
            REQUEST_AND_USE – create and send a request if
                necessary, or use the confirmation if it has been granted
                to open the Safe/file/password.
                
            CHECK_DON’T_USE – check if a request has been sent
                or, if not, create one and send an error. If a request is not
                needed, carry out the action.
                
            USE_ONLY – if the request has been confirmed, or if a
                request is not needed, open the Safe/file/password.
                
        Note: In version 4.1, this parameter has no default value and
        is obsolete. However, it can still be used as long as the
        ‘userequest’, ‘sendrequest’ and ‘executerequest’ parameters
        are not specified.

    .PARAMETER requestAccessType
        Whether the request is for a single or multiple access.
        Possible options are:
            SINGLE – for a single access.
            MULTIPLE – for multiple accesses

    .PARAMETER usableFrom
        The proposed date from when the request will be valid.

    .PARAMETER usableTo
        The proposed date until when the request will be valid.

    .PARAMETER requestReason
        The reason for the request.

    .PARAMETER userRequest
        If a confirmed request exists, it will be used to open the Safe
        and retrieve the specified password object.

    .PARAMETER sendRequest
        If a request is required to retrieve the selected password
        object, it will be sent.

    .PARAMETER executeRequest
        If a confirmed request exists or a request is not needed, the
        specified password object will be retrieved.

    .PARAMETER internalName
        The name of a previous password version.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$True)][string]$file,
        [Parameter(Mandatory=$True)][switch]$lockFile,
        [Parameter(Mandatory=$False)][switch]$evenIfLocked,
        [Parameter(Mandatory=$False)][ValidateSet("REQUEST_AND_USE","CHECK_DON’T_USE","USE_ONLY")][string]$requestUsageType,
        [Parameter(Mandatory=$False)][ValidateSet("SINGLE","MULTIPLE")][string]$requestAccessType,
        [Parameter(Mandatory=$False)][string]$usableFrom,
        [Parameter(Mandatory=$False)][string]$usableTo,
        [Parameter(Mandatory=$False)][string]$requestReason,
        [Parameter(Mandatory=$False)][switch]$userRequest,
        [Parameter(Mandatory=$False)][switch]$sendRequest,
        [Parameter(Mandatory=$False)][switch]$executeRequest,
        [Parameter(Mandatory=$False)][string]$internalName,        
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                        
        #execute pacli    
        $getPasswordObject = Invoke-Expression "$pacli RETRIEVEPASSWORDOBJECT $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
        
            #ignore whitespace
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
            If($getPasswordObject){
            
                ForEach($password in $getPasswordObject){
        
                    #define hash to hold values
                    $passwordObject = @{}
                    
                    $values = $password | ConvertFrom-PacliOutput
                    
                    #Add elements to hashtable
                    $passwordObject.Add("Password",$values[0])
                    
                    #return object from hashtable
                    New-Object -TypeName psobject -Property $passwordObject | select Password
                        
                }
            
            }
            
        }
        
    }
    
}

Function Lock-File{

    <#
    .SYNOPSIS
    	Locks a file or password, preventing other Users from retrieving it.

    .DESCRIPTION
    	Exposes the PACLI Function: "LOCKFILE"

    .PARAMETER vault
        The name of the Vault in which the file is stored.

    .PARAMETER user
        The Username of the User carrying out the task.

    .PARAMETER safe
        The name of the Safe in which the file is stored.

    .PARAMETER folder
        The name of the folder in which the file is stored.

    .PARAMETER file
        The name of the file or password to lock.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder = "Root",
        [Parameter(Mandatory=$True)][string]$file,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $lockFile = (Invoke-Expression "$pacli LOCKFILE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1

        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "Error Locking File: $file"
            Write-Debug $($lockFile|Out-String)
            #error Locking File, return false

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "$file Locked"
            #File Locked return true

            
        }
        
    }

}

Function Unlock-File{

    <#
    .SYNOPSIS
    	Unlocks a file or password, enabling other Users to retrieve it.

    .DESCRIPTION
    	Exposes the PACLI Function: "UNLOCKFILE"

    .PARAMETER vault
        The name of the Vault in which the file is stored.

    .PARAMETER user
        The Username of the User carrying out the task.

    .PARAMETER safe
        The name of the Safe in which the file is stored.

    .PARAMETER folder
        The name of the folder in which the file is stored.

    .PARAMETER file
        The name of the file or password to unlock.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder = "Root",
        [Parameter(Mandatory=$True)][string]$file,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $unlockFile = (Invoke-Expression "$pacli UNLOCKFILE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "Error Unlocking File: $file"
            Write-Debug $($unlockFile|Out-String)
            #error unlocking File, return false

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "$file Unlocked"
            #File unlocked return true

            
        }
        
    }

}

Function Move-File{

    <#
    .SYNOPSIS
    	Moves a file or password to a different folder within the same Safe.

    .DESCRIPTION
    	Exposes the PACLI Function: "MOVEFILE"

    .PARAMETER vault
        The name of the Vault in which the file is stored.

    .PARAMETER user
        The Username of the User carrying out the task.

    .PARAMETER safe
        The name of the Safe in which the file is stored.

    .PARAMETER folder
        The name of the folder in which the file is stored.

    .PARAMETER file
        The name of the file or password to move.

    .PARAMETER newFolder
        The name of the folder into which the file will be moved.
    
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$True)][string]$file,
        [Parameter(Mandatory=$True)][string]$newFolder,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $resetFile = (Invoke-Expression "$pacli MOVEFILE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Search-Files{

    <#
    .SYNOPSIS
    	Finds a particular file, list of files, password, or list of passwords, 
        according to the parameters set.

    .DESCRIPTION
    	Exposes the PACLI Function: "FINDFILES"

    .PARAMETER vault
        The name of the Vault containing the file(s) or password(s)
        you are looking for.

    .PARAMETER user
        The Username of the User carrying out the task.

    .PARAMETER safe
        The name of the Safe containing the file(s) or password(s)
        you are looking for. You can use a wildcard to specify a
        wider range of safenames.

    .PARAMETER folder
        The name of the folder containing the file(s) or password(s)
        to be found.

    .PARAMETER filePattern
        The full name or part of the name of the file(s) or
        password(s) to list. Alternatively, a wildcard can be used in
        this parameter.

    .PARAMETER fileRetrieved
        Whether or not the report will include retrieved files or
        passwords.

    .PARAMETER fileChanged
        Whether or not the report will include modified files or
        passwords.

    .PARAMETER fileNew
        Whether or not the report will include new files or
        passwords.

    .PARAMETER fileLocked
        Whether or not the report will include locked files or
        passwords.

    .PARAMETER fileWithNoMark
        Whether or not the report will include files or passwords
        without an access mark.

    .PARAMETER includeVersions
        Whether or not the report will include previous versions of
        included files or passwords.
        
        Note: If the value is set to NO, the ‘deletedoption’
        parameter cannot be set to INCLUDE_DELETED.

    .PARAMETER onlyOpenSafes
        Whether or not the report will search only Safes that are
        currently open

    .PARAMETER includeSubFolders
        Whether or not the search will include subfolders.

    .PARAMETER dateLimit
        A specific time duration. 
        Possible values are:
            NONE
            BETWEEN which is qualified by [fromdate] and [todate].
            PREVMONTH which is qualified by [prevcount].
            PREVDAY which is qualified by [prevcount].

    .PARAMETER dateActionLimit
        The activity that took place during the period specified in
        [datelimit]. 
        Possible values are:
            ACCESSEDFILE
            CREATED
            MODIFIED

    .PARAMETER prevCount
        The number of days or months to be included in the report if
        [datelimit] is specified as ‘PREVMONTH’ or ‘PREVDAY’.
    
    .PARAMETER fromDate
        The first day to be included in the report if [datelimit] is
        specified as ‘BETWEEN’. 
        Use the following date format:
            dd/mm/yyyy.
    
    .PARAMETER toDate
        The last day to be included in the report if [datelimit] is
        specified as ‘BETWEEN’. 
        Use the following date format:
            dd/mm/yyyy.

    .PARAMETER searchInAll
        Whether or not the report will only include files or passwords
        that contain the values specified in the ‘searchinallvalues’
        parameter in their Safe, folder or file/password name, or in
        one of their file categories, as specified in the
        ‘searchinallcategorylist’ parameter.

    .PARAMETER searchInAllAction
        The way that the values in the ‘searchinallvalues’ parameter
        will be searched for if the ‘searchinall’ parameter is set to
        ‘YES’. 
        Possible values are:
            ‘OR’ – at least one of the values in the list needs to be
            found.
            ‘AND’ – all the values in the list need to be found.

    .PARAMETER searchInAllValues
        A list of values that should be searched for when the
        ‘searchinall’ parameter is set to ‘YES’. The values in the list
        must be separated by the character specified in the
        ‘listseparator’ parameter.

    .PARAMETER searchInAllCategoryList
        A list of category names to search in when the ‘searchinall’
        parameter is set to ‘YES’. The values in the list must be
        separated by the character specified in the ‘listseparator’
        parameter.

    .PARAMETER listSeparator
        A character that will be used to separate the values in the
        ‘searchinallvalues’, ‘searchinallcategorylist’, ‘categoryidlist’,
        and ‘categoryvalues’ parameters. The default value is “,”
        (comma).
    
        Note: When a string with more than one character is
        specified, only the first character will be used.

    .PARAMETER deletedOption
        Whether or not deleted files will be shown in the report.
        Possible values are:
            INCLUDE_DELETED_WITH_ACCESSMARKS (default value)
            INCLUDE_DELETED
            ONLY_DELETED
            WITHOUT_DELETED
            
        Note: If the value is set to INCLUDE_DELETED, the
        ‘includeversions’ parameter cannot be set to NO.

    .PARAMETER sizeLimit
        The file or password size limit in KB for the search, based
        on the ‘sizelimittype’ parameter.

    .PARAMETER sizeLimitType
        The type of file or password size-based search. 
        Possible
        values are:
            ATLEAST
            ATMOST

    .PARAMETER categoryIDList
        A list of category IDs according to which the values
        specified in the ‘categoryvalues’ parameter will be searched
        for.
        
        Note: The first value corresponds to the first category, the
        second value to the second category, etc.
        Only files or passwords that contain the specified file
        categories (according to the ‘categorylistaction’ parameter)
        with the specified values will be returned.

    .PARAMETER categoryValues
        A list of values to search for in the file categories specified
        in the ‘categoryidlist’ parameter.
        
        Note: The first value corresponds to the first category, the
        second value to the second category, etc.
        Only files or passwords that contain the listed file categories
        (according to the ‘categorylistaction’ parameter) with the
        specified values will be returned.

    .PARAMETER categoryListAction
        Specifies how to search for the values in the ‘categoryidlist’
        and ‘categoryvalues’ parameters. 
        Possible values are:
            ‘OR’ – at least one of the values in the list needs to be
            found.
            ‘AND’ – all the values in the list need to be found.

    .PARAMETER includeFileCategories
        Whether or not the search will include file categories in the
        output.

    .PARAMETER fileCategoriesSeparator
        If the ‘includefilecategories’ parameter is set to ‘YES’, this
        character will be written in the search output to separate the
        file categories. The default value is ‘#’.

    .PARAMETER fileCategoryValueSeparator
        If the ‘includefilecategories’ parameter is set to ‘YES’, this
        character will be written in the search output to separate the
        file categories and their values. The default value is ‘:’.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$True)][string]$filePattern,
        [Parameter(Mandatory=$True)][switch]$fileRetrieved,
        [Parameter(Mandatory=$False)][switch]$fileChanged,
        [Parameter(Mandatory=$False)][switch]$fileNew,
        [Parameter(Mandatory=$False)][switch]$fileLocked,
        [Parameter(Mandatory=$False)][switch]$fileWithNoMark,
        [Parameter(Mandatory=$False)][switch]$includeVersions,
        [Parameter(Mandatory=$False)][switch]$onlyOpenSafes,
        [Parameter(Mandatory=$False)][switch]$includeSubFolders,
        [Parameter(Mandatory=$False)][ValidateSet("NONE","BETWEEN","PREVMONTH","PREVDAY")][string]$dateLimit,
        [Parameter(Mandatory=$False)][ValidateSet("ACCESSEDFILE","CREATED","MODIFIED")][string]$dateActionLimit,
        [Parameter(Mandatory=$False)][int]$prevCount,
        [Parameter(Mandatory=$False)]
            [ValidateScript({($_ -eq (get-date $_ -f dd/MM/yyyy))})]
                [string]$fromDate,
        [Parameter(Mandatory=$False)]
            [ValidateScript({($_ -eq (get-date $_ -f dd/MM/yyyy))})]
                [string]$toDate,
        [Parameter(Mandatory=$False)][switch]$searchInAll,
        [Parameter(Mandatory=$False)][ValidateSet("OR","AND")][string]$searchInAllAction,
        [Parameter(Mandatory=$False)][string]$searchInAllValues,
        [Parameter(Mandatory=$False)][string]$searchInAllCategoryList,
        [Parameter(Mandatory=$False)][string]$listSeparator,
        [Parameter(Mandatory=$False)][ValidateSet("INCLUDE_DELETED_WITH_ACCESSMARKS","INCLUDE_DELETED","ONLY_DELETED","WITHOUT_DELETED")]
            [string]$deletedOption,
        [Parameter(Mandatory=$False)][int]$sizeLimit,
        [Parameter(Mandatory=$False)][ValidateSet("ATLEAST","ATMOST")][string]$sizeLimitType,
        [Parameter(Mandatory=$False)][string]$categoryIDList,
        [Parameter(Mandatory=$False)][string]$categoryValues,
        [Parameter(Mandatory=$False)][ValidateSet("OR","AND")][string]$categoryListAction,
        [Parameter(Mandatory=$False)][switch]$includeFileCategories,
        [Parameter(Mandatory=$False)][string]$fileCategoriesSeparator,
        [Parameter(Mandatory=$False)][string]$fileCategoryValueSeparator,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                            
        #execute pacli    
        $searchFiles = Invoke-Expression "$pacli FINDFILES $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
        
            #ignore whitespace
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
            If($searchFiles){
            
                ForEach($file in $searchFiles){
        
                    #define hash to hold values
                    $filesList = @{}
                    
                    $values = $file | ConvertFrom-PacliOutput
                    
                    #Add elements to hashtable
                    $filesList.Add("Name",$values[0])
                    $filesList.Add("Accessed",$values[1])
                    $filesList.Add("CreationDate",$values[2])
                    $filesList.Add("CreatedBy",$values[3])
                    $filesList.Add("DeletionDate",$values[4])
                    $filesList.Add("DeletionBy",$values[5])
                    $filesList.Add("LastUsedDate",$values[6])
                    $filesList.Add("LastUsedBy",$values[7])
                    $filesList.Add("LockDate",$values[8])
                    $filesList.Add("LockedBy",$values[9])
                    $filesList.Add("LockedByGW",$values[10])
                    $filesList.Add("Size",$values[11])
                    $filesList.Add("History",$values[12])
                    $filesList.Add("InternalName",$values[13])
                    $filesList.Add("Safe",$values[14])
                    $filesList.Add("Folder",$values[15])
                    $filesList.Add("FileID",$values[16])
                    $filesList.Add("LockedByUserID",$values[17])
                    $filesList.Add("ValidationStatus",$values[18])
                    $filesList.Add("HumanCreationDate",$values[19])
                    $filesList.Add("HumanCreatedBy",$values[20])
                    $filesList.Add("HumanLastUsedDate",$values[21])                
                    $filesList.Add("HumanLastUsedBy",$values[22])
                    $filesList.Add("HumanLastRetrievedByDate",$values[23])
                    $filesList.Add("HumanLastRetrievedBy",$values[24])
                    $filesList.Add("ComponentCreationDate",$values[25])
                    $filesList.Add("ComponentCreatedBy",$values[26])
                    $filesList.Add("ComponentLastUsedDate",$values[27])
                    $filesList.Add("ComponentLastUsedBy",$values[28])   
                    $filesList.Add("ComponentLastRetrievedDate",$values[26])
                    $filesList.Add("ComponentLastRetrievedBy",$values[27])
                    $filesList.Add("FileCategories",$values[28])   
                    
                    #return object from hashtable
                    New-Object -TypeName psobject -Property $filesList | select Name, Accessed, CreationDate, CreatedBy, DeletionDate, DeletionBy, LastUsedDate, LastUsedBy,
                        LockDate, LockedBy, LockedByGW, Size, History, InternalName, Safe, Folder, FileID, LockedByUserID, ValidationStatus, HumanCreationDate, HumanCreatedBy,
                            HumanLastUsedDate, HumanLastUsedBy, HumanLastRetrievedByDate, HumanLastRetrievedBy, ComponentCreationDate, ComponentCreatedBy, ComponentLastUsedDate,
                                ComponentLastUsedBy, ComponentLastRetrievedDate, ComponentLastRetrievedBy, FileCategories
                        
                }
            
            }
            
        }
        
    }
    
}

Function Get-FilesList{

    <#
    .SYNOPSIS
    	Produces a list of files or passwords in the specified Safe that match 
        the criteria that is declared.

    .DESCRIPTION
    	Exposes the PACLI Function: "FILESLIST"

    .PARAMETER vault
        The name of the Vault containing the files to list.

    .PARAMETER user
        The Username of the User carrying out the task.

    .PARAMETER safe
        The name of the Safe containing the files to list.

    .PARAMETER folder
        The name of the folder containing the files to list.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                        
        #execute pacli    
        $files = Invoke-Expression "$pacli FILESLIST $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
        
            #ignore whitespace
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
            If($files){
            
                ForEach($file in $files){
        
                    #define hash to hold values
                    $filesList = @{}
                    
                    $values = $file | ConvertFrom-PacliOutput
                    
                    #Add elements to hashtable
                    $filesList.Add("Name",$values[0])
                    $filesList.Add("Accessed",$values[1])
                    $filesList.Add("CreationDate",$values[2])
                    $filesList.Add("CreatedBy",$values[3])
                    $filesList.Add("DeletionDate",$values[4])
                    $filesList.Add("DeletionBy",$values[5])
                    $filesList.Add("LastUsedDate",$values[6])
                    $filesList.Add("LastUsedBy",$values[7])
                    $filesList.Add("LockDate",$values[8])
                    $filesList.Add("LockedBy",$values[9])
                    $filesList.Add("LockedByGW",$values[10])
                    $filesList.Add("Size",$values[11])
                    $filesList.Add("History",$values[12])
                    $filesList.Add("Draft",$values[13])
                    $filesList.Add("RetrieveLock",$values[14])
                    $filesList.Add("InternalName",$values[15])
                    $filesList.Add("FileID",$values[16])
                    $filesList.Add("LockedByUserID",$values[17])
                    $filesList.Add("ValidationStatus",$values[18])
                    
                    #return object from hashtable
                    New-Object -TypeName psobject -Property $filesList | select Name, Accessed, CreationDate, CreatedBy, DeletionDate, DeletionBy, LastUsedDate, LastUsedBy,
                        LockDate, LockedBy, LockedByGW, Size, History, Draft, RetrieveLock, InternalName, FileID, LockedByUserID, ValidationStatus
                        
                }
            
            }
            
        }
        
    }
    
}

Function Get-FileVersionsList{

    <#
    .SYNOPSIS
    	Lists the versions of the specified file or password.

    .DESCRIPTION
    	Exposes the PACLI Function: "FILEVERSIONSLIST"

    .PARAMETER vault
        The name of the Vault containing the files to list.

    .PARAMETER user
        The Username of the User carrying out the task.

    .PARAMETER safe
        The name of the Safe in which the file is stored.

    .PARAMETER folder
        The name of the folder in which the file is stored.

    .PARAMETER file
        The name of the file or password whose versions will be displayed.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$True)][string]$file,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        #execute pacli    
        $files = Invoke-Expression "$pacli FILEVERSIONSLIST $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
        
            #ignore whitespace
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
            If($files){
            
                ForEach($file in $files){
        
                    #define hash to hold values
                    $filesList = @{}
                    
                    $values = $file | ConvertFrom-PacliOutput
                    
                    #Add elements to hashtable
                    $filesList.Add("Name",$values[0])
                    $filesList.Add("Accessed",$values[1])
                    $filesList.Add("CreationDate",$values[2])
                    $filesList.Add("CreatedBy",$values[3])
                    $filesList.Add("DeletionDate",$values[4])
                    $filesList.Add("DeletionBy",$values[5])
                    $filesList.Add("LastUsedDate",$values[6])
                    $filesList.Add("LastUsedBy",$values[7])
                    $filesList.Add("LockDate",$values[8])
                    $filesList.Add("LockedBy",$values[9])
                    $filesList.Add("Size",$values[10])
                    $filesList.Add("History",$values[11])
                    $filesList.Add("Draft",$values[12])
                    $filesList.Add("RetrieveLock",$values[13])
                    $filesList.Add("InternalName",$values[14])
                    $filesList.Add("FileID",$values[15])
                    $filesList.Add("LockedByUserID",$values[16])
                    $filesList.Add("ValidationStatus",$values[17])
                    
                    #return object from hashtable
                    New-Object -TypeName psobject -Property $filesList | select Name, Accessed, CreationDate, CreatedBy, DeletionDate, DeletionBy, LastUsedDate, LastUsedBy,
                        LockDate, LockedBy, Size, History, Draft, RetrieveLock, InternalName, FileID, LockedByUserID, ValidationStatus
                        
                }
            
            }
            
        }
        
    }
    
}

Function Reset-File{

    <#
    .SYNOPSIS
    	Reset the access marks on the specified file or password.

    .DESCRIPTION
    	Exposes the PACLI Function: "RESETFILE"

    .PARAMETER vault
        The name of the Vault in which the file is stored.

    .PARAMETER user
        The Username of the User carrying out the task.

    .PARAMETER safe
        The name of the Safe in which the file is stored.

    .PARAMETER folder
        The name of the folder in which the file is stored.

    .PARAMETER file
        The name of the file or password to reset.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$True)][string]$file,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $resetFile = (Invoke-Expression "$pacli RESETFILE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Get-FileActivity{

    <#
    .SYNOPSIS
    	Inspect activity that has taken place in a specified Safe.

    .DESCRIPTION
    	Exposes the PACLI Function: "INSPECTFILE"

    .PARAMETER vault
        The name of the Vault containing the appropriate file.

    .PARAMETER user
        The Username of the User carrying out the task.

    .PARAMETER safe
        The name of the Safe containing the file.

    .PARAMETER folder
        The folder containing the file whose activity will be listed.

    .PARAMETER file
        The name of the file or password whose activity will be listed.
        
    .PARAMETER logDays
        The number of days to include in the list of activities.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$True)][string]$file,
        [Parameter(Mandatory=$False)][int]$logDays,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                        
        #execute pacli    
        $fileActivities = Invoke-Expression "$pacli INSPECTFILE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
        
            #ignore whitespace
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
            If($fileActivities){
            
                ForEach($activity in $fileActivities){
        
                    #define hash to hold values
                    $activities = @{}
                    
                    $values = $activity | ConvertFrom-PacliOutput
                    
                    #Add elements to hashtable
                    $activities.Add("Time",$values[0])
                    $activities.Add("User",$values[1])
                    $activities.Add("Activity",$values[2])
                    $activities.Add("PreviousLocation",$values[3])
                    $activities.Add("RequestID",$values[4])
                    $activities.Add("RequestReason",$values[5])
                    $activities.Add("Code",$values[6])
                    
                    #return object from hashtable
                    New-Object -TypeName psobject -Property $activities | select Time, User, Activity, PreviousLocation, RequestID, RequestReason, Code
                        
                }
            
            }
            
        }
        
    }
    
}

Function Add-FileCategory{

    <#
    .SYNOPSIS
    	Adds a predefined File Category at Vault or Safe level to a file.

    .DESCRIPTION
    	Exposes the PACLI Function: "ADDFILECATEGORY"

    .PARAMETER vault
        The name of the Vault that the File Category is being added to.

    .PARAMETER user
        The Username of the User who is carrying out the task.

    .PARAMETER safe
        The name of the Safe that the File Category is being added to.

    .PARAMETER folder
        The folder containing a file with a File Category attached to it.

    .PARAMETER file
        The name of the file or password that is attached to a File Category.
        
    .PARAMETER category
        The name of the File Category.
        
    .PARAMETER value
        The value of the File Category for the file.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$False)][string]$vault,
        [Parameter(Mandatory=$False)][string]$user,
        [Parameter(Mandatory=$False)][string]$safe,
        [Parameter(Mandatory=$False)][string]$folder,
        [Parameter(Mandatory=$False)][string]$file,
        [Parameter(Mandatory=$False)][string]$category,
        [Parameter(Mandatory=$False)][string]$value,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $addCategory = (Invoke-Expression "$pacli ADDFILECATEGORY $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString -quoteOutput)") 2>&1
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            write-debug $($addCategory|out-string)
            #error adding category, return false

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            #category added return true

            
        }
        
    }
    
}

Function Update-FileCategory{

    <#
    .SYNOPSIS
    	Updates an existing File Category for a file or password.

    .DESCRIPTION
    	Exposes the PACLI Function: "UPDATEFILECATEGORY"

    .PARAMETER vault
        The name of the Vault where the File Category is being updated.

    .PARAMETER user
        The Username of the User who is carrying out the task.

    .PARAMETER safe
        The name of the Safe where the File Category is being updated.

    .PARAMETER folder
        The folder containing a file with a File Category attached to it.

    .PARAMETER file
        The name of the file or password that is attached to a File Category.
        
    .PARAMETER category
        The name of the File Category.
        
    .PARAMETER value
        The value of the File Category for the file.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder = "Root",
        [Parameter(Mandatory=$True)][string]$file,
        [Parameter(Mandatory=$True)][string]$category,
        [Parameter(Mandatory=$True)][string]$value,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $updateCategory = (Invoke-Expression "$pacli UPDATEFILECATEGORY $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1

        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "Error updating File Category: $category"
            Write-Debug $($updateCategory|Out-String)
            #error updating category, return false

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "File Category $category Updated"
            #category updated added return true

            
        }
        
    }
    
}

Function Remove-FileCategory{

    <#
    .SYNOPSIS
    	Deletes a category from a file or password's File Categories.

    .DESCRIPTION
    	Exposes the PACLI Function: "DELETEFILECATEGORY"

    .PARAMETER vault
        The name of the Vault where the File Category is being deleted.

    .PARAMETER user
        The Username of the User who is carrying out the task.

    .PARAMETER safe
        The name of the Safe where the File Category is being deleted.

    .PARAMETER folder
        The folder containing a file with a File Category attached to it.

    .PARAMETER file
        The name of the file or password that is attached to a File Category.
        
    .PARAMETER category
        The name of the File Category.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$True)][string]$file,
        [Parameter(Mandatory=$True)][string]$category,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $removeFileCategory = (Invoke-Expression "$pacli DELETEFILECATEGORY $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Get-FileCategories{

    <#
    .SYNOPSIS
    	Lists all the File Categories at both Vault and Safe level for the 
        specified file or password.

    .DESCRIPTION
    	Exposes the PACLI Function: "LISTFILECATEGORIES"

    .PARAMETER vault
        The name of the Vault containing the File Categories.

    .PARAMETER user
        The Username of the User who is carrying out the task.

    .PARAMETER safe
        The name of the Safe that the File Category is attached to.

    .PARAMETER folder
        The folder containing a file with a File Category attached to it.

    .PARAMETER file
        The name of the file or password that is attached to a File Category.
        
    .PARAMETER category
        The name of the File Category.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$True)][string]$file,
        [Parameter(Mandatory=$False)][string]$category,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        #execute pacli    
        $fileCategories = Invoke-Expression "$pacli LISTFILECATEGORIES $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
        
            #ignore whitespace
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
            If($fileCategories){
            
                ForEach($category in $fileCategories){
        
                    #define hash to hold values
                    $categories = @{}
                    
                    $values = $category | ConvertFrom-PacliOutput
                    
                    #Add elements to hashtable
                    $categories.Add("CategoryName",$values[0])
                    $categories.Add("CategoryValue",$values[1])
                    $categories.Add("CategoryID",$values[2])
                    
                    #return object from hashtable
                    New-Object -TypeName psobject -Property $categories | select CategoryName, CategoryValue, CategoryID
                        
                }
            
            }
            
        }
        
    }
    
}

Function Confirm-Object{

    <#
    .SYNOPSIS
    	Validates a file in a Safe that requires content validation before
        users can access the objects in it.

    .DESCRIPTION
    	Exposes the PACLI Function: "VALIDATEOBJECT"

    .PARAMETER vault
        The name of the Vault in which the file is stored.

    .PARAMETER user
        The Username of the User who is carrying out the task.

    .PARAMETER safe
        The name of the Safe in which the file is stored.

    .PARAMETER folder
        The name of the folder in which the file is stored.

    .PARAMETER file
        The name of the file to validate.
        
    .PARAMETER internalName
        The internal name of the file version to validate
        
    .PARAMETER validationAction
        The type of validation action that take place. 
        Possible values are:
            VALID
            INVALID
            PENDING

    .PARAMETER reason
        The reason for validating the file.
    
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$True)][string]$object,
        [Parameter(Mandatory=$True)][string]$internalName,
        [Parameter(Mandatory=$True)][ValidateSet("VALID","INVALID","PENDING")][string]$validationAction,
        [Parameter(Mandatory=$True)][string]$reason,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $confirmObject = (Invoke-Expression "$pacli VALIDATEOBJECT $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)") 2>&1
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Get-HttpGwUrl{

    <#
    .SYNOPSIS
    	Retrieves the HTTP Gateway URL for a file in the Safe. 
        Note: This command is no longer supported in version 5.5.

    .DESCRIPTION
    	Exposes the PACLI Function: "GETHTTPGWURL"

    .PARAMETER vault
        The name of the Vault containing the specified Safe.

    .PARAMETER user
        The name of the user carrying out the task.

    .PARAMETER safe
        The name of the Safe that contains the file.

    .PARAMETER folder
        The name of the folder where the file is stored.

    .PARAMETER file
        The name of the specified file.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$folder,
        [Parameter(Mandatory=$True)][string]$file,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        #execute pacli    
        $httpGwUrl = Invoke-Expression "$pacli GETHTTPGWURL $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
        
            #ignore whitespace
            Select-String -Pattern "\S"
        
        if($LASTEXITCODE){
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            write-debug "LastExitCode: $LASTEXITCODE"
            
            If($httpGwUrl){
            
                ForEach($gwURL in $httpGwUrl){
        
                    #define hash to hold values
                    $urls = @{}
                    
                    $values = $gwURL | ConvertFrom-PacliOutput
                    
                    #Add elements to hashtable
                    $urls.Add("URL",$values[0])
                    
                    #return object from hashtable
                    New-Object -TypeName psobject -Property $urls | select URL
                        
                }
            
            }
            
        }
        
    }
    
}

Function Add-Rule{

    <#
    .SYNOPSIS
    	Adds an Object Level Access rule

    .DESCRIPTION
    	Exposes the PACLI Function: "ADDRULE"

    .PARAMETER vault
        The name of the Vault.

    .PARAMETER user
        The Username of the User who is logged on.

    .PARAMETER userName
        The user who will be affected by the rule.

    .PARAMETER safeName
    The Safe where the rule is applied.

    .PARAMETER fullObjectName
        The file, password, or folder that the rule applies to.

    .PARAMETER isFolder
        Whether the rule applies to files and passwords or for
        folders.
            NO – Indicates files and passwords
            YES – Indicates folders

    .PARAMETER effect
        Whether or not the rule allows or denies the user
        authorizations that are specified in the following parameters.
        Possible values are:
            Allow – The rule enables the authorizations marked ‘YES’.
            Deny – The rule denies all the following permissions.

    .PARAMETER retrieve
        Whether or not the user is authorized to retrieve files.

    .PARAMETER store
        Whether or not the user is authorized to store files.

    .PARAMETER delete
        Whether or not the user is authorized to delete files.

    .PARAMETER administer
        Whether or not the user is authorized to administer the Safe.

    .PARAMETER supervise
        Whether or not the user is authorized to supervise other Safe
        Owners and confirm requests by other users to enter specific
        Safes

    .PARAMETER backup
        Whether or not the user is authorized to backup the Safe

    .PARAMETER manageOwners
        Whether or not the user is authorized to manage other Safe
        owners.

    .PARAMETER accessNoConfirmation
        Whether or not the user is authorized to access the Safe
        without receiving confirmation from authorized users.

    .PARAMETER validateSafeContent
        Whether or not the user is authorized to validate the Safe
        contents.

    .PARAMETER list
        Whether or not the user is authorized to list the specified file,
        password, or folder.

    .PARAMETER usePassword
        If the object is a password, whether or not the user can use
        the password via the PVWA.

    .PARAMETER updateObjectProperties
        Whether or not the user is authorized to update the specified
        file or password categories.

    .PARAMETER initiateCPMChange
        Whether or not the user is authorized to initiate a CPM
        change for the specified password.

    .PARAMETER initiateCPMChangeWithManualPassword
        Whether or not the user is authorized to initiate a CPM
        change with a manual password for the specified password.

    .PARAMETER createFolder
        Whether or not the user is authorized to create a new folder.

    .PARAMETER deleteFolder
        Whether or not the user is authorized to delete a folder.

    .PARAMETER moveFrom
        Whether or not the user is authorized to move the specified
        file or password from its current location.

    .PARAMETER moveInto
        Whether or not the user is authorized to move the specified
        file or password into a different location.

    .PARAMETER viewAudit
        Whether or not the user is authorized to view the specified
        file or password audits.

    .PARAMETER viewPermissions
        Whether or not the user is authorized to view the specified
        file or password permissions.

    .PARAMETER eventsList
        Whether or not the user is authorized to view events.
        
        Note: To allow Safe Owners to access the Safe, make sure
        this is set to YES.

    .PARAMETER addEvents
        Whether or not the user is authorized to add events.

    .PARAMETER createObject
        Whether or not the user is authorized to create a new file or
        password.

    .PARAMETER unlockObject
        Whether or not the user is authorized to unlock the specified
        file or password.

    .PARAMETER renameObject
        Whether or not the user is authorized to rename the
        specified file or password.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$userName,
        [Parameter(Mandatory=$True)][string]$safeName,
        [Parameter(Mandatory=$True)][string]$fullObjectName,
        [Parameter(Mandatory=$False)][switch]$isFolder,
        [Parameter(Mandatory=$True)][ValidateSet("Allow","Deny")][string]$effect,
        [Parameter(Mandatory=$False)][switch]$retrieve,
        [Parameter(Mandatory=$False)][switch]$store,
        [Parameter(Mandatory=$False)][switch]$delete,
        [Parameter(Mandatory=$False)][string]$administer,
        [Parameter(Mandatory=$False)][string]$supervise,
        [Parameter(Mandatory=$False)][string]$backup,
        [Parameter(Mandatory=$False)][string]$manageOwners,
        [Parameter(Mandatory=$False)][string]$accessNoConfirmation,
        [Parameter(Mandatory=$False)][string]$validateSafeContent,
        [Parameter(Mandatory=$False)][string]$list,
        [Parameter(Mandatory=$False)][string]$usePassword,
        [Parameter(Mandatory=$False)][string]$updateObjectProperties,
        [Parameter(Mandatory=$False)][string]$initiateCPMChange,
        [Parameter(Mandatory=$False)][string]$initiateCPMChangeWithManualPassword,
        [Parameter(Mandatory=$False)][string]$createFolder,
        [Parameter(Mandatory=$False)][string]$deleteFolder,
        [Parameter(Mandatory=$False)][string]$moveFrom,
        [Parameter(Mandatory=$False)][string]$moveInto,
        [Parameter(Mandatory=$False)][string]$viewAudit,
        [Parameter(Mandatory=$False)][string]$viewPermissions,
        [Parameter(Mandatory=$False)][string]$eventsList,
        [Parameter(Mandatory=$False)][string]$addEvents,
        [Parameter(Mandatory=$False)][string]$createObject,
        [Parameter(Mandatory=$False)][string]$unlockObject,
        [Parameter(Mandatory=$False)][string]$renameObject,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        #define hash to hold values
        $details = @{}
        
        $addRule = Invoke-Expression "$pacli ADDRULE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
            
            #ignore whitespaces, return string
            Select-String -Pattern "\S" | Out-String
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            
            if($addRule){
            
                ForEach($rule in $addRule){
                
                    $values = $rule | ConvertFrom-PacliOutput

                    #Add elements to hashtable
                    $details.Add("RuleID",$values[0])
                    $details.Add("UserName",$values[1])
                    $details.Add("SafeName",$values[2])
                    $details.Add("FullObjectName",$values[3])
                    $details.Add("Effect",$values[4])
                    $details.Add("RuleCreationDate",$values[5])
                    $details.Add("AccessLevel",$values[6])                      
                    
                    #return object from hashtable
                    New-Object -TypeName psobject -Property $details | select RuleID, UserName, SafeName, FullObjectName, Effect, RuleCreationDate, AccessLevel
                    
                }
            
            }
            
        }
        
    }

}

Function Remove-Rule{

    <#
    .SYNOPSIS
    	Deletes a service rule

    .DESCRIPTION
    	Exposes the PACLI Function: "DELETERULE"

    .PARAMETER vault
        The name of the Vault.

    .PARAMETER user
        The Username of the User who is logged on.

    .PARAMETER ruleID
        The unique ID of the rule to delete.

    .PARAMETER userName
        The user who will be affected by the rule.

    .PARAMETER safeName
        The Safe where the rule is applied.

    .PARAMETER fullObjectName
        The file, password, or folder that the rule applies to.
    
    .PARAMETER isFolder
        Whether the rule applies to files and passwords or for folders.
            NO – Indicates files and passwords
            YES – Indicates folders
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$ruleID,
        [Parameter(Mandatory=$True)][string]$userName,
        [Parameter(Mandatory=$True)][string]$safeName,
        [Parameter(Mandatory=$True)][string]$fullObjectName,
        [Parameter(Mandatory=$False)][switch]$isFolder,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $deleteRule = Invoke-Expression "$pacli DELETERULE $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Get-RulesList{

    <#
    .SYNOPSIS
    	Lists all the service rules in a specified Safe.

    .DESCRIPTION
    	Exposes the PACLI Function: "RULESLIST"

    .PARAMETER vault
        The name of the Vault.

    .PARAMETER user
        The Username of the User who is logged on.

    .PARAMETER safeName
        The Safe where the ruls are applied.

    .PARAMETER fullObjectName
        The file, password, or folder that the rule applies to.
        
    .PARAMETER isFolder
        Whether the rule applies to files and passwords or for folders.
            NO – Indicates files and passwords
            YES – Indicates folders
            
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safeName,
        [Parameter(Mandatory=$True)][string]$fullObjectname,
        [Parameter(Mandatory=$False)][switch]$isFolder,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        #define hash to hold values
        $details = @{}
        
        $rulesList = Invoke-Expression "$pacli RULESLIST $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
            
            #ignore whitespaces, return string
            Select-String -Pattern "\S" | Out-String
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            
            if($rulesList){
            
                ForEach($rule in $rulesList){
                
                    $values = $rule | ConvertFrom-PacliOutput

                    #Add elements to hashtable
                    $details.Add("RuleID",$values[0])
                    $details.Add("UserName",$values[1])
                    $details.Add("SafeName",$values[2])
                    $details.Add("FullObjectName",$values[3])
                    $details.Add("Effect",$values[4])
                    $details.Add("RuleCreationDate",$values[5])
                    $details.Add("AccessLevel",$values[6])                    
                    
                    #return object from hashtable
                    New-Object -TypeName psobject -Property $details | select RuleID, UserName, SafeName, FullObjectName, Effect, RuleCreationDate, AccessLevel
                
                }
                
            }
            
        }
        
    }

}

###Request Functions###

Function Get-RequestsList{

    <#
    .SYNOPSIS
    	Lists requests from users who wish to enter Safes that require manual 
        access confirmation from authorized users.

    .DESCRIPTION
    	Exposes the PACLI Function: "REQUESTSLIST"

    .PARAMETER vault
        The name of the Vault containing the specified Safe.

    .PARAMETER user
        The Username of the User carrying out the task.

    .PARAMETER requestsType
        The type of requests to display. 
        The options are:
        		MY_REQUESTS – your user requests for access.
        		INCOMING_REQUESTS – other users’ requests for you
                    to authorize.
                ALL_REQUESTS – other users’ requests as well as
                    your own user requests (in the  CyberArk Vault
                    version 3.5 and above).

    .PARAMETER requestorPattern
        Pattern of the username of the user who created the request.

    .PARAMETER safePattern
        Pattern of the Safe specified in the request.

    .PARAMETER objectPattern
        Pattern of the file or password specified in the request.
        Note: This parameter specifies the full object name, including
        the folder. Either specify the full name of a specific object, or
        use an asterisk (*) before the object name.

    .PARAMETER waiting
        Whether or not the request is waiting for a response.

    .PARAMETER confirmed
        Whether or not the request is waiting for a confirmation.

    .PARAMETER displayInvalid
        Whether to display all requests or only invalid ones. 
        The options are:
        		ALL_REQUESTS
        		ONLY_VALID
        		ONLY_INVALID

    .PARAMETER includeAlreadyHandled
        Whether to include requests that have already been handled
        in the list of requests.

    .PARAMETER requestID
        The unique ID number of the request.

    .PARAMETER objectsType
        The type of operation that generated this request. 
        Possible values:
        		ALL_OBJECTS
        		GET_FILE
        		GET_PASSWORD
        		OPEN_SAFE
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$False)][ValidateSet("MY_REQUESTS","INCOMING_REQUESTS","ALL_REQUESTS")][string]$requestsType,
        [Parameter(Mandatory=$False)][string]$requestorPattern,
        [Parameter(Mandatory=$False)][string]$safePattern,
        [Parameter(Mandatory=$False)][string]$objectPattern,
        [Parameter(Mandatory=$False)][switch]$waiting,
        [Parameter(Mandatory=$False)][switch]$confirmed,
        [Parameter(Mandatory=$False)][ValidateSet("ALL_REQUESTS","ONLY_VALID","ONLY_INVALID")][string]$displayInvalid,
        [Parameter(Mandatory=$False)][switch]$includeAlreadyHandled,
        [Parameter(Mandatory=$False)][string]$requestID,
        [Parameter(Mandatory=$False)][ValidateSet("ALL_OBJECTS","GET_FILE","GET_PASSWORD","OPEN_SAFE")][string]$objectsType,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                        
        #define hash to hold values
        $details = @{}
        
        $requestsList = Invoke-Expression "$pacli REQUESTSLIST $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
            
            #ignore whitespaces, return string
            Select-String -Pattern "\S" | Out-String
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            
            if($requestsList){
            
                ForEach($request in $requestsList){
                
                    $values = $request | ConvertFrom-PacliOutput

                    #Add elements to hashtable
                    $details.Add("RequestID",$values[0])
                    $details.Add("User",$values[1])
                    $details.Add("Operation",$values[2])
                    $details.Add("Safe",$values[3])
                    $details.Add("File",$values[4])
                    $details.Add("Confirmed",$values[5])
                    $details.Add("Reason",$values[6])
                    $details.Add("Status",$values[7])
                    $details.Add("InvalidReason",$values[8])
                    $details.Add("Confirmations",$values[9])
                    $details.Add("Rejections",$values[10])
                    $details.Add("ConfirmationsLeft",$values[11])
                    $details.Add("CreationDate",$values[12])
                    $details.Add("LastUsedDate",$values[13])
                    $details.Add("ExpirationDate",$values[14])
                    $details.Add("AccessType",$values[15])
                    $details.Add("UsableFrom",$values[16])
                    $details.Add("UsableTo",$values[17])
                    $details.Add("SafeID",$values[18])
                    $details.Add("UserID",$values[19])
                    $details.Add("FileID",$values[20])                        
                    
                    #return object from hashtable
                    New-Object -TypeName psobject -Property $details | select RequestID, User, Operation, Safe, File, Confirmed, Reason, Status, 
                        InvalidReason, Confirmations, Rejections, ConfirmationsLeft, CreationDate, LastUsedDate, ExpirationDate, AccessType, 
                            UsableFrom, UsableTo, SafeID, UserID, FileID
                
                }
                
            }
            
        }
        
    }

}

Function Confirm-Request{

    <#
    .SYNOPSIS
    	Enables authorized users or groups to confirm a request.

    .DESCRIPTION
    	Exposes the PACLI Function: "CONFIRMREQUEST"

    .PARAMETER vault
        The name of the Vault containing the specified Safe.

    .PARAMETER user
        The Username of the User carrying out the task.

    .PARAMETER safe
        The name of the Safe for which the request has been created.
    
    .PARAMETER requestID
        The unique ID number of the request.
    
    .PARAMETER confirm
        Whether to confirm or reject this request.

    .PARAMETER reason
        The reason for the action taken by the authorized user or group.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$requestID,
        [Parameter(Mandatory=$True)][string]$confirm,
        [Parameter(Mandatory=$False)][string]$reason,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        #define hash to hold values
        $details = @{}
        
        $confirmRequest = Invoke-Expression "$pacli CONFIRMREQUEST $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
            
            #ignore whitespaces, return string
            Select-String -Pattern "\S" | Out-String
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            
            if($confirmRequest){
            
                ForEach($request in $confirmRequest){
                
                    $values = $request | ConvertFrom-PacliOutput

                    #Add elements to hashtable
                    $details.Add("RequestID",$values[0])
                    $details.Add("User",$values[1])
                    $details.Add("Operation",$values[2])
                    $details.Add("Safe",$values[3])
                    $details.Add("File",$values[4])
                    $details.Add("Confirmed",$values[5])
                    $details.Add("Reason",$values[6])
                    $details.Add("Status",$values[7])
                    $details.Add("InvalidReason",$values[8])
                    $details.Add("Confirmations",$values[9])
                    $details.Add("Rejections",$values[10])
                    $details.Add("ConfirmationsLeft",$values[11])
                    $details.Add("CreationDate",$values[12])
                    $details.Add("LastUsedDate",$values[13])
                    $details.Add("ExpirationDate",$values[14])
                    $details.Add("AccessType",$values[15])
                    $details.Add("UsableFrom",$values[16])
                    $details.Add("UsableTo",$values[17])
                    $details.Add("SafeID",$values[18])
                    $details.Add("UserID",$values[19])
                    $details.Add("FileID",$values[20])                        
                    
                    #return object from hashtable
                    New-Object -TypeName psobject -Property $details | select RequestID, User, Operation, Safe, File, Confirmed, Reason, Status, 
                        InvalidReason, Confirmations, Rejections, ConfirmationsLeft, CreationDate, LastUsedDate, ExpirationDate, AccessType, 
                            UsableFrom, UsableTo, SafeID, UserID, FileID
                
                }
                
            }
            
        }
        
    }

}

Function Remove-Request{

    <#
    .SYNOPSIS
    	Removes a request from the requests list. If the request is removed from 
        the MY_REQUEST list, it is deleted. If it is removed from the 
        INCOMING_REQUEST list, the user who issued this function will not be able 
        to see it, but other authorized users will be able to.

    .DESCRIPTION
        Exposes the PACLI Function: "DELETEREQUEST"

    .PARAMETER vault
        The name of the Vault containing the specified Safe.

    .PARAMETER user
        The Username of the User carrying out the task.

    .PARAMETER safe
        The name of the Safe for which the request has been created.
    
    .PARAMETER requestID
        The unique ID number of the request.
    
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$requestID,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $deleteRequest = Invoke-Expression "$pacli DELETEREQUEST $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Get-RequestConfirmationStatus{

    <#
    .SYNOPSIS
    	Displays the status of confirmation for a specific request.

    .DESCRIPTION
    	Exposes the PACLI Function: "REQUESTCONFIRMATIONSTATUS"

    .PARAMETER vault
        The name of the Vault containing the specified Safe.

    .PARAMETER user
        The Username of the User carrying out the task.

    .PARAMETER safe
        The name of the Safe for which the request has been created.
    
    .PARAMETER requestID
        The unique ID number of the request.
    
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$vault,
        [Parameter(Mandatory=$True)][string]$user,
        [Parameter(Mandatory=$True)][string]$safe,
        [Parameter(Mandatory=$True)][string]$requestID,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        #define hash to hold values
        $details = @{}
        
        $requestStatus = Invoke-Expression "$pacli REQUESTCONFIRMATIONSTATUS $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
            
            #ignore whitespaces, return string
            Select-String -Pattern "\S" | Out-String
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            
            if($requestStatus){
            
                ForEach($request in $requestStatus){
                
                    $values = $request | ConvertFrom-PacliOutput

                    #Add elements to hashtable
                    $details.Add("UserName",$values[0])
                    $details.Add("GroupName",$values[1])
                    $details.Add("Action",$values[2])
                    $details.Add("ActionDate",$values[3])
                    $details.Add("Reason",$values[4])
                    $details.Add("UserID",$values[5])
                    $details.Add("GroupID",$values[6])
                    
                    #return object from hashtable
                    New-Object -TypeName psobject -Property $details | select UserName, GroupName, Action, ActionDate, Reason, UserID, GroupID
                
                }
                
            }
            
        }
        
    }

}

###Password Functions###

Function New-Password{

    <#
    .SYNOPSIS
    	Generates a password automatically according to the built-in password 
        policy, and the user-specified policy.

    .DESCRIPTION
        Exposes the PACLI Function: "GENERATEPASSWORD"
    	The built-in policy ensures the following:
            Numbers will not occur in the password edges
            Repeated characters or sequences are not allowed
        The user-specified policy enables the user to control the parameters 
        that are specified in this command

    .PARAMETER length
    	The length of the password.

    .PARAMETER minUpperCase
    	The minimum number of uppercase characters to be included
    	in the password. Specify ‘-1’ to exclude uppercase characters
    	from the password.

    .PARAMETER minSpecial
    	The minimum number of special characters to be included in
    	the password. Specify ‘-1’ to exclude special characters from
    	the password.

    .PARAMETER minLowerCase
    	The minimum number of lowercase characters to be included
    	in the password. Specify ‘-1’ to exclude lowercase characters
    	from the password.

    .PARAMETER minDigit
    	The minimum number of numeric characters to be included in
    	the password. Specify ‘-1’ to exclude digits from the
    	password.

    .PARAMETER effectiveLength
    	The number of characters from the beginning of the password
    	that the above 4 parameters apply to.

    .PARAMETER forbiddenChars
    	A list of characters that will not be included in the password.
    	These characters do not have separators, but must be inside
    	quotation marks, eg., “/?\”
    
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$True)][int]$length,
        [Parameter(Mandatory=$False)][int]$minUpperCase,
        [Parameter(Mandatory=$False)][int]$minSpecial,
        [Parameter(Mandatory=$False)][int]$minLowerCase,
        [Parameter(Mandatory=$False)][int]$minDigit,
        [Parameter(Mandatory=$False)][int]$effectiveLength,
        [Parameter(Mandatory=$False)][string]$forbiddenChars,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $generatePassword = (Invoke-Expression "$pacli GENERATEPASSWORD $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'") 2>&1

        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "Error Generating Password"
            Write-Debug $($generatePassword|Out-String)

            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            Write-Verbose "Password Generated"
            #Return Generated Password String
            [string]$generatePassword
            
        }
        
    }

}

###Session Management Functions###

Function Get-CtlFileName{

    <#
    .SYNOPSIS
    	Returns the name of the Certificate Trust List (CTL) that was defined 
        during the Start-Pacli function.

    .DESCRIPTION
    	Exposes the PACLI Function: "CTLGETFILENAME"

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $ctlFileName = Invoke-Expression "$pacli CTLGETFILENAME $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
            
            #ignore whitespaces, return string
            Select-String -Pattern "\S" | Out-String
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            
            if($ctlFileName){
            
                ForEach($fileName in $ctlFileName){
                
                    $values = $fileName | ConvertFrom-PacliOutput

                    #define hash to hold values
                    $details = @{}
            
                    #Add elements to hashtable
                    $details.Add("Name",$values[0])
                    
                    #return object from hashtable
                    New-Object -TypeName psobject -Property $details | select Name
                
                }
                
            }
            
        }
        
    }

}

Function Add-CTLCert{

    <#
    .SYNOPSIS
    	Adds a certificate to the Certificate Trust List store.

    .DESCRIPTION
    	Exposes the PACLI Function: "CTLADDCERT"

    .PARAMETER ctlFileName
    	The name of the CTL file to the CTL store. If this parameter is not
        supplied, the CTL file name that was supplied in the INIT function
        is used.

    .PARAMETER certFileName
        The full path and name of the certificate file.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$False)][string]$ctlFileName,
        [Parameter(Mandatory=$False)][string]$certFileName,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $addCTLCert = Invoke-Expression "$pacli CTLADDCERT $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Remove-CTLCert{

    <#
    .SYNOPSIS
    	Removes a certificate from the Certificate Trust List store.

    .DESCRIPTION
    	Exposes the PACLI Function: "CTLREMOVECERT"

    .PARAMETER ctlFileName
    	The name of the CTL file to remove from the CTL store. If this
        parameter is not supplied, the CTL file name that was supplied in
        the INIT function is used.

    .PARAMETER certFileName
        The full path and name of the certificate file.
        
    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$False)][string]$ctlFileName,
        [Parameter(Mandatory=$False)][string]$certFileName,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $removeCTLCert = Invoke-Expression "$pacli CTLREMOVECERT $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString)"
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"

            
        }
        
    }

}

Function Get-CtlList{

    <#
    .SYNOPSIS
    	Lists all the certificates in the Certificate Trust List store.

    .DESCRIPTION
    	Exposes the PACLI Function: "CTLLIST"

    .PARAMETER ctlFileName
    	The name of the CTL file that contains the certificates to list. If this
        parameter is not supplied, the CTL file name that was supplied in
        the INIT function is used.

    .PARAMETER sessionID
    	The ID number of the session. Use this parameter when working
        with multiple scripts simultaneously. The default is ‘0’.

    .EXAMPLE
    	A sample command that uses the function or script, optionally followed
    	by sample output and a description. Repeat this keyword for each example.

    .NOTES
    	AUTHOR: Pete Maan
    	LASTEDIT: January 2015
    #>
    
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory=$False)][string]$ctlFileName,
        [Parameter(Mandatory=$False)][int]$sessionID
    )

    If(!(Test-ExePreReqs)){

            #$pacli variable not set or not a valid path

    }

    Else{

        #$PACLI variable set to executable path
                    
        $ctlList = Invoke-Expression "$pacli CTLLIST $($PSBoundParameters.getEnumerator() | ConvertTo-ParameterString) OUTPUT '(ALL,ENCLOSE)'" | 
            
            #ignore whitespaces, return string
            Select-String -Pattern "\S" | Out-String
        
        if($LASTEXITCODE){
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            
        }
        
        Else{
        
            Write-Debug "LastExitCode: $LASTEXITCODE"
            
            if($ctlList){
            
                ForEach($ctl in $ctlList){
                
                    $values = $ctl | ConvertFrom-PacliOutput

                    #define hash to hold values
                    $details = @{}
            
                    #Add elements to hashtable
                    $details.Add("Subject",$values[0])
                    $details.Add("Issuer",$values[0])
                    $details.Add("FromDate",$values[0])
                    $details.Add("ToDate",$values[0])
                    
                    #return object from hashtable
                    New-Object -TypeName psobject -Property $details | select Subject, Issuer, FromDate, ToDate
                
                }
                
            }
            
        }
        
    }

}

###Export Module Member Commands###
Export-ModuleMember -Function Initialize-PoShPACLI

Export-ModuleMember -Function Start-Pacli #INIT
Export-ModuleMember -Function Stop-Pacli #TERM
Export-ModuleMember -Function Add-VaultDefinition #DEFINE
Export-ModuleMember -Function Read-VaultConfigFile #DEFINEFROMFILE
Export-ModuleMember -Function Remove-VaultDefinition #DELETEVAULT
Export-ModuleMember -Function Connect-Vault #LOGON
Export-ModuleMember -Function New-LogonFile #CREATELOGONFILE
Export-ModuleMember -Function Disconnect-Vault #LOGOFF
Export-ModuleMember -Function Set-Password #SETPASSWORD
Export-ModuleMember -Function Lock-User #LOCK
Export-ModuleMember -Function Unlock-User #UNLOCK
Export-ModuleMember -Function Add-User #ADDUSER
Export-ModuleMember -Function Update-User #UPDATEUSER
Export-ModuleMember -Function Rename-User #RENAMEUSER
Export-ModuleMember -Function Remove-User #DELETEUSER
Export-ModuleMember -Function Add-ExternalUser #ADDUPDATEEXTERNALUSERENTITY
Export-ModuleMember -Function Get-UserDetails #USERDETAILS
Export-ModuleMember -Function Get-VaultUsers #USERSLIST
Export-ModuleMember -Function Get-UserActivity #INSPECTUSER
Export-ModuleMember -Function Get-SafesLog #SAFESLOG
Export-ModuleMember -Function Clear-UserHistory #CLEARUSERHISTORY
Export-ModuleMember -Function Set-UserPhoto #PUTUSERPHOTO
Export-ModuleMember -Function Get-UserPhoto #GETUSERPHOTO
Export-ModuleMember -Function Send-PAMailMessage #MAILUSER
Export-ModuleMember -Function Add-SafeShare #ADDSAFESHARE
Export-ModuleMember -Function Remove-SafeShare #DELETESAFESHARE
Export-ModuleMember -Function Add-Group #ADDGROUP
Export-ModuleMember -Function Update-Group #UPDATEGROUP
Export-ModuleMember -Function Remove-Group #DELETEGROUP
Export-ModuleMember -Function Add-GroupMember #ADDGROUPMEMBER
Export-ModuleMember -Function Remove-GroupMember #DELETEGROUPMEMBER
Export-ModuleMember -Function Add-Location #ADDLOCATION
Export-ModuleMember -Function Update-Location #UPDATELOCATION
Export-ModuleMember -Function Rename-Location #RENAMELOCATION
Export-ModuleMember -Function Remove-Location #DELETELOCATION
Export-ModuleMember -Function Get-Locations #LOCATIONSLIST
Export-ModuleMember -Function Get-GroupDetails #GROUPDETAILS
Export-ModuleMember -Function Get-GroupMembers #GROUPMEMBERS
Export-ModuleMember -Function Add-LDAPBranch #LDAPBRANCHADD
Export-ModuleMember -Function Update-LDAPBranch #LDAPBRANCHUPDATE
Export-ModuleMember -Function Remove-LDAPBranch #LDAPBRANCHDELETE
Export-ModuleMember -Function Get-LDAPBranches #LDAPBRANCHESLIST
Export-ModuleMember -Function Add-NetworkArea #ADDNETWORKAREA
Export-ModuleMember -Function Remove-NetworkArea #DELETENETWORKAREA
Export-ModuleMember -Function Move-NetworkArea #MOVENETWORKAREA
Export-ModuleMember -Function RenameNetworkArea #RENAMENETWORKAREA
Export-ModuleMember -Function Get-NetworkArea #NETWORKAREASLIST
Export-ModuleMember -Function Add-AreaAddress #ADDAREAADDRESS
Export-ModuleMember -Function Remove-AreaAddress #DELETEAREAADDRESS
Export-ModuleMember -Function Add-TrustedNetworkArea #ADDTRUSTEDNETWORKAREA
Export-ModuleMember -Function Remove-TrustedNetworkArea #DELETETRUSTEDNETWORKAREA
Export-ModuleMember -Function Get-TrustedNetworkArea #TRUSTEDNETWORKAREALIST
Export-ModuleMember -Function Enable-TrustedNetworkArea #ACTIVATETRUSTEDNETWORKAREA
Export-ModuleMember -Function Disable-TrustedNetworkArea #DEACTIVATETRUSTEDNETWORKAREA
Export-ModuleMember -Function Open-Safe #OPENSAFE
Export-ModuleMember -Function Close-Safe #CLOSESAFE
Export-ModuleMember -Function Add-Safe #ADDSAFE
Export-ModuleMember -Function Update-Safe #UPDATESAFE
Export-ModuleMember -Function Rename-Safe #RENAMESAFE
Export-ModuleMember -Function Remove-Safe #DELETESAFE
Export-ModuleMember -Function Add-SafeOwner #ADDOWNER
Export-ModuleMember -Function Update-SafeOwner #UPDATEOWNER
Export-ModuleMember -Function Remove-SafeOwner #DELETEOWNER
Export-ModuleMember -Function Get-OwnerSafes #OWNERSAFESLIST
Export-ModuleMember -Function Get-SafeDetails #SAFEDETAILS
Export-ModuleMember -Function Get-Safe #SAFESLIST
Export-ModuleMember -Function Get-SafeOwners #OWNERSLIST
Export-ModuleMember -Function Get-SafeActivity #INSPECTSAFE
Export-ModuleMember -Function Add-SafeFileCategory #ADDSAFEFILECATEGORY
Export-ModuleMember -Function Update-SafeFileCategory #UPDATESAFEFILECATEGORY
Export-ModuleMember -Function Remove-SafeFileCategory #DELETESAFEFILECATEGORY
Export-ModuleMember -Function Get-SafeFileCategory #LISTSAFEFILECATEGORIES
Export-ModuleMember -Function Add-SafeEvent #ADDEVENT
Export-ModuleMember -Function Get-SafeEvents #SAFEEVENTSLIST
Export-ModuleMember -Function Add-SafeNote #ADDNOTE
Export-ModuleMember -Function Reset-Safe #RESETSAFE
Export-ModuleMember -Function Clear-SafeHistory #CLEARSAFEHISTORY
Export-ModuleMember -Function Add-Folder #ADDFOLDER
Export-ModuleMember -Function Remove-Folder #DELETEFOLDER
Export-ModuleMember -Function RestoreFolder #UNDELETEFOLDER
Export-ModuleMember -Function Move-Folder #MOVEFOLDER
Export-ModuleMember -Function Get-Folder #FOLDERSLIST
Export-ModuleMember -Function Add-PreferredFolder #ADDPREFERREDFOLDER
Export-ModuleMember -Function Remove-PreferredFolder #DELETEPREFFEREDFOLDER
Export-ModuleMember -Function Add-File #STOREFILE
Export-ModuleMember -Function Get-File #RETRIEVEFILE
Export-ModuleMember -Function Remove-File #DELETEFILE
Export-ModuleMember -Function Restore-File #UNDELETEFILE
Export-ModuleMember -Function Add-PasswordObject #STOREPASSWORDOBJECT
Export-ModuleMember -Function Get-PasswordObject #RETRIEVEPASSWORDOBJECT
Export-ModuleMember -Function Lock-File #LOCKFILE
Export-ModuleMember -Function Unlock-File #UNLOCKFILE
Export-ModuleMember -Function Move-File #MOVEFILE
Export-ModuleMember -Function Search-Files #FINDFILES
Export-ModuleMember -Function Get-FilesList #FILESLIST
Export-ModuleMember -Function Get-FileversionsList #FILEVERSIONSLIST
Export-ModuleMember -Function Reset-File #RESETFILE
Export-ModuleMember -Function Get-FileActivity #INSPECTFILE
Export-ModuleMember -Function Add-FileCategory #ADDFILECATEGORY
Export-ModuleMember -Function Update-FileCategory #UPDATEFILECATEGORY
Export-ModuleMember -Function Remove-FileCategory #DELETEFILECATEGORY
Export-ModuleMember -Function Get-FileCategories #LISTFILECATEGORIES
Export-ModuleMember -Function Confirm-Object #VALIDATEOBJECT
Export-ModuleMember -Function Get-HttpGwUrl #GETHTTPGWURL
Export-ModuleMember -Function Add-Rule #ADDRULE
Export-ModuleMember -Function Remove-Rule #DELETERULE
Export-ModuleMember -Function Get-RulesList #RULESLIST
Export-ModuleMember -Function Get-RequestsList #REQUESTSLIST
Export-ModuleMember -Function Confirm-Request #CONFIRMREQUEST
Export-ModuleMember -Function Remove-Request #DELETEREQUEST
Export-ModuleMember -Function Get-RequestConfirmationStatus #REQUESTCONFIRMATIONSTATUS
Export-ModuleMember -Function New-Password #GENERATEPASSWORD
Export-ModuleMember -Function Get-CtlFileName #CTLGETFILENAME
Export-ModuleMember -Function Add-CTLCert #CTLADDCERT
Export-ModuleMember -Function Remove-CTLCert #CTLREMOVECERT
Export-ModuleMember -Function Get-CtlList #CTLLIST
Export-ModuleMember -Function New-Password #GENERATEPASSWORD
Export-ModuleMember -Function Get-CtlFileName #CTLGETFILENAME
Export-ModuleMember -Function Add-CTLCert #CTLADDCERT
Export-ModuleMember -Function Remove-CTLCert #CTLREMOVECERT
Export-ModuleMember -Function Get-CtlList #CTLLIST
