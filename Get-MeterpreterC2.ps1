 function Get-MeterpreterC2 {
<#
    .SYNOPSIS

        Author: Jayden Zheng (@fuseyjz)

        Check the carved memory file for presence of Meterpreter C2.

    .EXAMPLE
     
        PS C:\> Get-MeterpreterC2 -Path C:\Users\countercept\Desktop\0x084d0000.infected
          __  __     _                        _              ___ ___
         |  \/  |___| |_ ___ _ _ _ __ _ _ ___| |_ ___ _ _   / __|_  )
         | |\/| / -_)  _/ -_) '_| '_ \ '_/ -_)  _/ -_) '_| | (__ / /
         |_|  |_\___|\__\___|_| | .__/_| \___|\__\___|_|    \___/___|
                                |_|
        https://192.168.1.178:443 

        PS C:\Users\countercept\Desktop> Get-MeterpreterC2 -Path .\0x084d0000.infected
          __  __     _                        _              ___ ___
         |  \/  |___| |_ ___ _ _ _ __ _ _ ___| |_ ___ _ _   / __|_  )
         | |\/| / -_)  _/ -_) '_| '_ \ '_/ -_)  _/ -_) '_| | (__ / /
         |_|  |_\___|\__\___|_| | .__/_| \___|\__\___|_|    \___/___|
                                |_|
        https://192.168.1.178:443

    .REQUIREMENT

        Powershell 5.0 above for Format-Hex usage.
#>
 
    [CmdletBinding()] 
    Param (
        [Parameter()] 
        [String] $Path
    )

    if ($Path) {
        if (Test-Path $Path) {
            if ($Path.Contains('.\')) {
                $FilePath = Split-Path $Path
                $Resolve = Resolve-Path $FilePath
                $ResolvedPath = $Resolve.Path
                $FileName = $Path.replace(".\","")
                $getPath = "$ResolvedPath\$FileName"
            }
            else {
                $getPath = $Path
            }
        }
        else {
            Write-Host "[*] Invalid file path!"
        }
    }
    else {
        Write-Host "[*] Error, please enter the file path with -Path parameter."
    }
            
    # function from https://cyber-defense.sans.org/blog/2010/02/11/powershell-byte-array-hex-convert
    function Convert-HexStringToByteArray
    {
        [CmdletBinding()]
        Param ( [Parameter(Mandatory = $True, ValueFromPipeline = $True)] [String] $String )

        #Clean out whitespaces and any other non-hex crud.
        $String = $String.ToLower() -replace '[^a-f0-9\\,x\-\:]',"

        #Try to put into canonical colon-delimited format.
        $String = $String -replace '0x|\x|\-|,',':'

        #Remove beginning and ending colons, and other detritus.
        $String = $String -replace '^:+|:+$|x|\',"

        #Maybe there's nothing left over to convert...
        if ($String.Length -eq 0) { ,@() ; return }

        #Split string with or without colon delimiters.
        if ($String.Length -eq 1)
            { ,@([System.Convert]::ToByte($String,16)) }
        elseif (($String.Length % 2 -eq 0) -and ($String.IndexOf(":") -eq -1))
            { ,@($String -split '([a-f0-9]{2})' | foreach-object { if ($_) {[System.Convert]::ToByte($_,16)}}) }
        elseif ($String.IndexOf(":") -ne -1)
            { ,@($String -split ':+' | foreach-object {[System.Convert]::ToByte($_,16)}) }
        else
            { ,@() }
    }

    if ($getPath) {
        # Read all bytes of the carved file
        $Bytes = [System.IO.File]::ReadAllBytes($getPath)

        $Hex = ($Bytes | Format-Hex | Select-Object -Expand Bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ''

        # Find the markers and cut off
        $regexMarker = "0000e01d2a0a"
        $regexMarker2 = "f0b5a256803a09"
        $matchMarker = [regex]::Match($Hex, $regexMarker)
        $matchMarker2 = [regex]::Match($Hex, $regexMarker2)

        if ($matchMarker.Index -ne 0) { $markerIndex = $matchMarker.Index }
        elseif ($matchMarker2.Index -ne 0) { $markerIndex = $matchMarker2.Index }
        else { Write-Host "[*] Header marker not found in this dump." }

        if ($markerIndex) {
            $chopMarker = $Hex.Substring($markerIndex)

            # Protocol filter for TCP, UDP, HTTP(s), SMB, Named Pipe
            $regexTcp = "740063007000"
            $regexUdp = "750064007000"
            $regexHttp = "6800740074007000"
            $regexSmb = "73006d006200"
            $regexPipe = "7000690070006500"
            $matchTcp = [regex]::Match($chopMarker, $regexTcp)
            $matchUdp = [regex]::Match($chopMarker, $regexUdp)
            $matchHttp = [regex]::Match($chopMarker, $regexHttp)
            $matchSmb = [regex]::Match($chopMarker, $regexSmb)
            $matchPipe = [regex]::Match($chopMarker, $regexPipe)

            if ($matchTcp.Index -ne 0) { $getIndex = $matchTcp.Index }
            elseif ($matchUdp.Index -ne 0) { $getIndex = $matchUdp.Index }
            elseif ($matchHttp.Index -ne 0) { $getIndex = $matchHttp.Index }
            elseif ($matchSmb.Index -ne 0) { $getIndex = $matchSmb.Index }
            elseif ($matchPipe.Index -ne 0) { $getIndex = $matchPipe.Index }
            else { Write-Host "[*] No protocol was found in this dump." }

            if ($getIndex) {
                # Cut off extra before C2
                $chopC2 = $chopMarker.Substring($getIndex)

                # Cut off extra after C2
                $regexZeros = "00000000000000000000"
                $matchZeros = [regex]::Match($chopC2, $regexZeros)
                $indexZeros = $matchZeros.Index
                $chopFinal = $chopC2.Substring(0, $indexZeros)

                # Conversion
                $Out = Convert-HexStringToByteArray $chopFinal
                $Output = [System.Text.Encoding]::Unicode.GetString($Out)

                if ($Output) {
                    Write-Host "  __  __     _                        _              ___ ___ "
                    Write-Host " |  \/  |___| |_ ___ _ _ _ __ _ _ ___| |_ ___ _ _   / __|_  )"
                    Write-Host " | |\/| / -_)  _/ -_) '_| '_ \ '_/ -_)  _/ -_) '_| | (__ / / "
                    Write-Host " |_|  |_\___|\__\___|_| | .__/_| \___|\__\___|_|    \___/___|"
                    Write-Host "                        |_|                                  "
                    Write-Host "$output"
                }
            }
        }
    }
}
