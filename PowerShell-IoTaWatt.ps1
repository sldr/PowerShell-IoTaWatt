# MIT License
# 
# Copyright (c) 2022 Stephen L. De Rudder
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

Function Format-Bytes {
    Param
    (
        [Parameter(ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [float]$number
    )
    Begin{
    }
    Process {
        if ($number -lt 1KB) {
            return "$number B"
        } elseif ($number -lt 1MB) {
            $number = $number / 1KB
            $number = "{0:N2}" -f $number
            return "$number KB"
        } elseif ($number -lt 1GB) {
            $number = $number / 1MB
            $number = "{0:N2}" -f $number
            return "$number MB"
        } elseif ($number -lt 1TB) {
            $number = $number / 1GB
            $number = "{0:N2}" -f $number
            return "$number GB"
        } elseif ($number -lt 1PB) {
            $number = $number / 1TB
            $number = "{0:N2}" -f $number
            return "$number TB"
        } else {
            $number = $number / 1PB
            $number = "{0:N2}" -f $number
            return "$number PB"
        }
    }
    End{
    }
}

Function Drop-FristAndLastChar {
    [CmdletBinding()]
    Param
    (
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [string[]]$String
    )
    Begin{
    }
    Process {
        $String.ForEach( { if ($_.Length -le 2) { Write-Output "" } else { Write-Output $_.Substring(1, $_.Length - 2) } })
    }
    End{
    }
}

Function Convert-FromUnixTimeToLocal($CTime) {
    ([datetime] '1970-01-01Z').ToUniversalTime().AddSeconds($CTime).ToLocalTime()
}

Function Convert-FromUnixTimeToUTC($CTime) {
    ([datetime] '1970-01-01Z').ToUniversalTime().AddSeconds($CTime)
}

Function Convert-FromUnixTimeToLocalString($CTime, $Format="o") {
    (([datetime] '1970-01-01Z').ToUniversalTime().AddSeconds($CTime).ToLocalTime()).ToString($Format)
}

Function Convert-FromUnixTimeToUTCString($CTime, $Format="o") {
    (([datetime] '1970-01-01Z').ToUniversalTime().AddSeconds($CTime)).ToString($Format)
}

Function Get-IotAWattStatus {
    [CmdletBinding()]
    Param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Computer,
        [Parameter(Position = 1)]
        [PSCredential]$Credential
    )
    Begin{
    }
    Process {
    }
    End{
        $URI = 'http://' + $Computer + '/status?state&inputs&outputs&stats&wifi&datalogs&influx1&influx2&emoncms&pvoutput'
        Invoke-RestMethod -Uri $URI -Credential $Credential
    }
}

Function Write-IotAWattStats {
    [CmdletBinding()]
    Param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$Status,
        [Parameter()]
        [switch]$UTCTime
    )
    Begin{
    }
    Process {
        if ($Status.GetType().Name -ne 'PSCustomObject') {
            throw 'The Status parameter must be of type PSCustomObject (usually obtained from Get-IotAWattStatus command)'
        }
        if ($Status.psobject.Properties.Item('stats') -eq $null) {
            throw 'The Status parameter must have a stats property (usually obtained from Get-IotAWattStatus command)'
        }
        Write-Output "Firmware version: $($Status.stats.version)"
        if ($UTCTime) {
            Write-Output "Start time: $((Convert-FromUnixTimeToUTC -CTime $Status.stats.starttime).ToString("o"))"
            Write-Output "Current time: $((Convert-FromUnixTimeToUTC -CTime $Status.stats.currenttime).ToString("o"))"
        } else {
            Write-Output "Start time: $((Convert-FromUnixTimeToLocal -CTime $Status.stats.starttime).ToString("o"))"
            Write-Output "Current time: $((Convert-FromUnixTimeToLocal -CTime $Status.stats.currenttime).ToString("o"))"
        }
        Write-Output "Running time: $((New-TimeSpan -Seconds $Status.stats.runseconds).ToString('%d"d "%h"h "%m"m "%s"s"'))"
        Write-Output "Free heap: $($Status.stats.stack)"
        Write-Output "Frequency: $($Status.stats.frequency) Hz"
        Write-Output "Samples per AC cycle: $($Status.stats.cyclerate)"
        Write-Output "AC cycles sampled/second: $($Status.stats.chanrate)"
        Write-Output ""
    }
    End{
    }
}

Function Write-IotAWattDataLogs($Status, $UTCTime=$false) {
    $LogName = "Current"
    $Log = $Status.datalogs[0]
    if ($UTCTime) {
        $StartTimeStr = (Convert-FromUnixTimeToUTC -CTime $Log.firstkey).ToString("o")
        $EndTimeStr = (Convert-FromUnixTimeToUTC -CTime $Log.lastkey).ToString("o")
    } else {
        $StartTimeStr = (Convert-FromUnixTimeToLocal -CTime $Log.firstkey).ToString("o")
        $EndTimeStr = (Convert-FromUnixTimeToLocal -CTime $Log.lastkey).ToString("o")
    }
    Write-Output "$LogName Log: $StartTimeStr - $EndTimeStr Size: $(Format-Bytes $Log.size) ($($Log.size) bytes) Rec Interval: $($Log.interval) secs"
    $LogName = "History"
    $Log = $Status.datalogs[1]
    if ($UTCTime) {
        $StartTimeStr = (Convert-FromUnixTimeToUTC -CTime $Log.firstkey).ToString("o")
        $EndTimeStr = (Convert-FromUnixTimeToUTC -CTime $Log.lastkey).ToString("o")
    } else {
        $StartTimeStr = (Convert-FromUnixTimeToLocal -CTime $Log.firstkey).ToString("o")
        $EndTimeStr = (Convert-FromUnixTimeToLocal -CTime $Log.lastkey).ToString("o")
    }
    Write-Output "$LogName Log: $StartTimeStr - $EndTimeStr Size: $(Format-Bytes $Log.size) ($($Log.size) bytes) Rec Interval: $($Log.interval) secs"
}

Function Get-IotAWattSeries {
    [cmdletbinding()]
    Param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Computer,
        [Parameter(Position = 1)]
        [PSCredential]$Credential
    )
    Begin{
        $ret = $null
    }
    Process {
    }
    End{
        $URI = 'http://' + $Computer + '/query?show=series'
        Write-Verbose "URI=$URI"
        $Series = Invoke-RestMethod -Uri $URI -Credential $Credential
        Write-Debug 'Invoke-RestMethod finished'
        if ($Series.GetType().Name -eq 'PSCustomObject') {
            Write-Debug 'Invoke-RestMethod returned a PSCustomObject as expected'
            if ($Series.psobject.Properties.Item('series') -ne $null) {
                Write-Debug 'The PSCustomObject has series property as expected'
                $Series = $Series.series
                $Series | ForEach-Object { $I = $_; $I | Add-Member -MemberType NoteProperty -Name Unit -Value $_.unit -Force }
                $Series | Add-Member -MemberType AliasProperty -Name Series -Value name
                #$J = $Series | Select-Object Series, Unit
                #$o = Get-Member -InputObject $J
                #Write-Verbose "$o"
                #$J | ForEach-Object { Write-Verbose "$_" }
                $ret = $Series | Select-Object Series, Unit
                return $ret
            } else {
                throw "Get-IotAWattSeries failed calling Invoke-RestMethod with unexpected return of $Series"
            }
        } else {
            throw "Get-IotAWattSeries failed calling Invoke-RestMethod with unexpected return of $Series"
        }
    }
}

Function Get-IotAWattQuery {
    [CmdletBinding(DefaultParameterSetName = 'SomeSeriesSpec')]
    Param
    (
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'AllSeriesSpec')]
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'SomeSeriesSpec')]
        [ValidateNotNullOrEmpty()]
        [string]$Computer,
        [Parameter(Position = 1, ParameterSetName = 'AllSeriesSpec')]
        [Parameter(Position = 1, ParameterSetName = 'SomeSeriesSpec')]
        [PSCredential]$Credential,
        [Parameter(ParameterSetName = 'AllSeriesSpec')]
        [Parameter(ParameterSetName = 'SomeSeriesSpec')]
        [string]$Begin,
        [Parameter(ParameterSetName = 'AllSeriesSpec')]
        [Parameter(ParameterSetName = 'SomeSeriesSpec')]
        [string]$End,
        [Parameter(ParameterSetName = 'AllSeriesSpec')]
        [Parameter(ParameterSetName = 'SomeSeriesSpec')]
        [string]$Group="auto",
        [Parameter(ParameterSetName = 'AllSeriesSpec')]
        [Parameter(ParameterSetName = 'SomeSeriesSpec')]
        [ValidateSet("null","skip","zero",IgnoreCase=$true)]
        $Missing,
        [Parameter(ParameterSetName = 'AllSeriesSpec')]
        [Parameter(ParameterSetName = 'SomeSeriesSpec')]
        [ValidateSet("json","csv",IgnoreCase=$true)]
        $Format="json",
        [Parameter(ParameterSetName = 'AllSeriesSpec')]
        [Parameter(ParameterSetName = 'SomeSeriesSpec')]
        [switch]$Header,
        [Parameter(ParameterSetName = 'SomeSeriesSpec')]
        [string[]]$Series,
        [Parameter(ParameterSetName = 'AllSeriesSpec')]
        [switch]$AllSeries,
        [Parameter(ParameterSetName = 'AllSeriesSpec')]
        [ValidateSet("time.utc.iso","time.utc.unix","time.local.iso","time.local.unix")]
        [Alias("Time1")]
        $Time,
        [Parameter(ParameterSetName = 'AllSeriesSpec')]
        [ValidateSet("time.utc.iso","time.utc.unix","time.local.iso","time.local.unix")]
        $Time2,
        [Parameter(ParameterSetName = 'AllSeriesSpec')]
        [ValidateSet("time.utc.iso","time.utc.unix","time.local.iso","time.local.unix")]
        $Time3,
        [Parameter(ParameterSetName = 'AllSeriesSpec')]
        [ValidateSet("time.utc.iso","time.utc.unix","time.local.iso","time.local.unix")]
        $Time4
    )
    Begin{
        if ($PSCmdlet.ParameterSetName -eq 'AllSeriesSpec') {
            Write-Verbose "Using AllSeries"
            [System.Collections.ArrayList]$FinalArray = @()
            Get-IotAWattSeries -Computer $Computer -Credential $Credential | ForEach-Object { $FinalArray.Add("$($_.Series).$($_.Unit)") *>$null }
            $UseSeries = $FinalArray
            if ($Time4 -ne $null) {
                $UseSeries.Insert(0, $Time4.ToString())
            }
            if ($Time3 -ne $null) {
                $UseSeries.Insert(0, $Time3.ToString())
            }
            if ($Time2 -ne $null) {
                $UseSeries.Insert(0, $Time2.ToString())
            }
            if ($Time -ne $null) {
                $UseSeries.Insert(0, $Time.ToString())
            }
            $UseSeries = $UseSeries.ToArray()
        } else {
            $UseSeries = $Series
        }
        if ($Header) {
            $HeaderString="yes"
        } else {
            $HeaderString="no"
        }
        $UseSeriesString = [string]::Join(",", $UseSeries)
        Write-Verbose "Series=$UseSeriesString"
        Write-Verbose "PSCmdlet.ToString()=$($PSCmdlet.ToString())"
        Write-Verbose "PSCmdlet.MyInvocation.PSCommandPath=$($PSCmdlet.MyInvocation.PSCommandPath)"
        Write-Verbose "PSCmdlet.MyInvocation.PSScriptRoot=$($PSCmdlet.MyInvocation.PSScriptRoot)"
        Write-Verbose "PSCmdlet.MyInvocation.ScriptName=$($PSCmdlet.MyInvocation.ScriptName)"
        Write-Verbose "PSCmdlet.MyInvocation.InvocationName=$($PSCmdlet.MyInvocation.InvocationName)"
    }
    Process {
    }
    End{
        #$URI = 'http://' + $Computer + '/query?select=[time.utc.iso,time.local.iso,time.utc.unix,time.local.unix,Main_1,Main_2]&begin='+$Begin+'&end='+$End+'&group='+$Group+'&format=json&header=yes'
        $URI = 'http://' + $Computer + '/query?select=['+$UseSeriesString+']&begin='+$Begin+'&end='+$End+'&group='+$Group+'&format='+$Format+'&header='+$HeaderString+'&missing='+$Missing
        Write-Verbose "URI=$URI"
        $Ret = Invoke-RestMethod -Uri $URI -Credential $cred -TimeoutSec 5
        return $Ret
    }
}

Function Backup-IotAWattDataLogs {
    [CmdletBinding()]
    Param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Computer,
        [Parameter(Position = 1, Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Position = 2)]
        [PSCredential]$Credential,
        [ValidateSet("json","csv",IgnoreCase=$true)]
        $Format="csv",
        [Parameter()]
        [ValidateSet("time.utc.iso","time.utc.unix","time.local.iso","time.local.unix")]
        [Alias("Time1")]
        $Time,
        [Parameter()]
        [ValidateSet("time.utc.iso","time.utc.unix","time.local.iso","time.local.unix")]
        $Time2,
        [Parameter()]
        [ValidateSet("time.utc.iso","time.utc.unix","time.local.iso","time.local.unix")]
        $Time3,
        [Parameter()]
        [ValidateSet("time.utc.iso","time.utc.unix","time.local.iso","time.local.unix")]
        $Time4
    )
    Begin{
        ####
        # Get all series from Get-IotAWattSeries
        $Series = Get-IotAWattSeries -Computer $Computer -Credential $Credential
        [System.Collections.ArrayList]$FinalArray = @()
        Get-IotAWattSeries -Computer $Computer -Credential $Credential | ForEach-Object { $FinalArray.Add("$($_.Series).$($_.Unit)") *>$null }
        $UseSeries = $FinalArray
        if ($Time4 -ne $null) {
            $UseSeries.Insert(0, $Time4.ToString())
        }
        if ($Time3 -ne $null) {
            $UseSeries.Insert(0, $Time3.ToString())
        }
        if ($Time2 -ne $null) {
            $UseSeries.Insert(0, $Time2.ToString())
        }
        if ($Time -ne $null) {
            $UseSeries.Insert(0, $Time.ToString())
        }
        $UseSeries = $UseSeries.ToArray()
        ####
        # Get datalogs info from Get-IotAWattStatus
        $Status = Get-IotAWattStatus -Computer $Computer -Credential $Credential
        $Interval = $Status.datalogs[0].interval
        $FirstKey = $Status.datalogs[0].firstkey
        Write-Verbose "FirstKey: $FirstKey $(Convert-FromUnixTimeToUTCString -CTime $FirstKey) $(Convert-FromUnixTimeToLocalString -CTime $FirstKey)"
        $LastKey = $Status.datalogs[0].lastkey + 5 # last key is never sent
        Write-Verbose "LastKey : $LastKey $(Convert-FromUnixTimeToUTCString -CTime $LastKey) $(Convert-FromUnixTimeToLocalString -CTime $LastKey)"
        $NextKey = $FirstKey + $Interval * 500
        if ($NextKey -gt $LastKey) {
            $NextKey = $LastKey
        }
        Write-Verbose "NextKey : $NextKey $(Convert-FromUnixTimeToUTCString -CTime $NextKey) $(Convert-FromUnixTimeToLocalString -CTime $NextKey)"
        ###
        # Setup filepath with JSON Array in file or create empty for csv
        if ($Format -eq "json") {
            '{"labels":' | Out-File -FilePath $FilePath -Encoding ascii
            $d = Get-IotAWattQuery -Computer $Computer -Credential $Credential -Begin $FirstKey -End $NextKey -Group "5s" -Missing skip -Format $Format -Header -Series $UseSeries
            $d[0].labels  | ConvertTo-Json -Compress | Out-File -FilePath $FilePath -Encoding ascii -Append
            ',"data":[' | Out-File -FilePath $FilePath -Encoding ascii -Append
        } else {
            $null | Out-File -FilePath $FilePath -Encoding ascii
        }

    }
    Process {
        $FirstIteration = $true
        $HeaderValue = $false
        $ConsecutiveErrorCount = 0
        while ($FirstKey -lt $LastKey) {
            if ($FirstIteration) {
                if ($Format -eq "csv") {
                    $HeaderValue=$true
                }
            } else {
                $HeaderValue = $false
                if ($Format -eq "json") {
                    "," | Out-File -FilePath $FilePath -Encoding ascii -Append
                }
            }
            try {
                if ($Format -eq "json") {
                    $Data = Get-IotAWattQuery -Computer $Computer -Credential $Credential -Begin $FirstKey -End $NextKey -Group "5s" -Missing skip -Format $Format -Series $UseSeries
                } else {
                    $Data = Get-IotAWattQuery -Computer $Computer -Credential $Credential -Begin $FirstKey -End $NextKey -Group "5s" -Missing skip -Format $Format -Series $UseSeries -Header:$HeaderValue
                }
            } catch [System.Net.WebException] {
                $ConsecutiveErrorCount += 1
                if ($ConsecutiveErrorCount -gt 3) {
                    Write-Error $Error[0].Exception.ToString()
                    throw
                }
                Write-Verbose "Retring due to WebException: $($Error[0].Exception.GetType().FullName): $($Error[0].Exception.Message)"
                continue
            } catch [Exception] {
                $ConsecutiveErrorCount += 1
                if ($ConsecutiveErrorCount -gt 3) {
                    Write-Error $Error[0].Exception.ToString()
                    throw
                }
                Write-Verbose "Retring due to unexpected Exception: $($Error[0].Exception.GetType().FullName): $($Error[0].Exception.Message)"
                continue
            } catch {
                Write-Error "Failed due to unexpected catch: $($Error[0].ToString())"
                throw
            }
            $FirstIteration = $false
            $ConsecutiveErrorCount = 0
            if ($Format -eq "json") {
                $Data | ConvertTo-Json -Compress | Drop-FristAndLastChar | Out-File -FilePath $FilePath -Encoding ascii -Append
            } else {
                $Data | Out-File -FilePath $FilePath -Encoding ascii -Append
            }
            Start-Sleep -Seconds 1
            $FirstKey = $NextKey
            $NextKey = $FirstKey + $Interval * 500
            if ($NextKey -gt $LastKey) {
                $NextKey = $LastKey
            }
            Write-Verbose "FirstKey: $FirstKey $(Convert-FromUnixTimeToUTCString -CTime $FirstKey) $(Convert-FromUnixTimeToLocalString -CTime $FirstKey)"
            Write-Verbose "NextKey : $NextKey $(Convert-FromUnixTimeToUTCString -CTime $NextKey) $(Convert-FromUnixTimeToLocalString -CTime $NextKey)"
            Write-Verbose "LastKey : $LastKey $(Convert-FromUnixTimeToUTCString -CTime $LastKey) $(Convert-FromUnixTimeToLocalString -CTime $LastKey)"
        }
    }
    End{
        if ($Format -eq "json") {
            "]}" | Out-File -FilePath $FilePath -Encoding ascii -Append
        }
    }
}
