Function write-log {
  param (
  $message,
  $sev = "INFO",
  $D = 0,
  $MainVars,
  [string]$ErrorCode
  ) 

  if ($Global:LogWriter -eq "Ghost"){
    write-Ghost -message $message -sev $Sev -errorcde $Errorcode
  } else {
    ## This write log module is designed for nutanix calm output
    if ($message -match "Task .* Completed"){
      $global:stoptime = Get-Date
    } 
    if ($Global:error -and $debug -ge 4){
      write-host "'$(get-date -format "dd-MMM-yy HH:mm:ss")' |'WARN' | Errorlog is not empty, '$($Global:error.count)' Errors" -ForegroundColor  Yellow
    }
    if ($sev -eq "INFO" -and $Debug -ge $D){
      write-host "'$(get-date -format "dd-MMM-yy HH:mm:ss")' | INFO  | $message "
    } elseif ($sev -eq "WARN"){
      write-host "'$(get-date -format "dd-MMM-yy HH:mm:ss")' |'WARN' | $ErrorCode $message " -ForegroundColor  Yellow
    } elseif ($sev -eq "ERROR"){
      write-host "'$(get-date -format "dd-MMM-yy HH:mm:ss")' |'ERROR'| $ErrorCode $message " -ForegroundColor  Red
      write-error $message -ea:0 # Calm stops, no powershell error.
  
      if ($PSVersionTable.PSVersion.Major -ne 5){
        $Global:MyExit = 1
        sleep 10
        if ($MyExit -eq 1){
          $global:LASTEXITCODE = 1
        }
      }
      if ($GlobalPsInvokeRetryCounter -ge 5){
        write-host "'$(get-date -format "dd-MMM-yy HH:mm:ss")' |'ERROR'| 0 Global Retry Counter is greater than '5', breaking out." -ForegroundColor  Red
        break
      }
    } elseif ($sev -match "CHAPTER"){
      write-host ""
      write-host "####################################################################"
      write-host "#                                                                  #"
      write-host "#     $message"
      if ($message -match "Task .* Completed"){
        $timespan = New-TimeSpan -Start $starttime -End $stoptime
        write-host "#                                                                  #"
        write-host "#     Runtime took '$($timespan.days)' days, '$($timespan.hours)' hours, '$($timespan.minutes)' minutes, '$($timespan.seconds) seconds'"
        write-host "#                                                                  #"
      } elseif ($sev -match "MasterCHAPTER"){
        write-host "#                                                                  #"
        write-host "#                                                                  #"
        write-host "#                                                                  #"  
        write-host "#                                                                  #"  
        write-host "# Framework Load Completed. Please follow the output below.        #"  
      } else {
        write-host "#                                                                  #"
      }
      write-host "####################################################################"
      write-host ""
    }
  }
} 

Function write-Ghost {
  param (
  $message,
  $sev = "INFO",
  $D = 0,
  $MainVars,
  [string]$ErrorCode
  ) 
  ## This write log module is designed for Tripwire

  if (!$Global:logfile){
    write-log -message "Ghost Writer Cannot Start, Global Logging Var is not defined." -sev "ERROR" -Errorcode "0"
    break
  } elseif (!(get-content $Global:logfile -ea:4)){
    "Starting Ghost Logger" | out-file $Logfile 
  }
  if ($message -match "Task .* Completed"){
    $global:stoptime = Get-Date
  } 
  if ($Global:error -and $debug -ge 4){
    "'$(get-date -format "dd-MMM-yy HH:mm:ss")' |'WARN' | Errorlog is not empty, '$($Global:error.count)' Errors" | out-file $Logfile -append
  }
  if ($sev -eq "INFO" -and $Debug -ge $D){
    "'$(get-date -format "dd-MMM-yy HH:mm:ss")' | INFO  | $message " | out-file $Logfile -append
  } elseif ($sev -eq "WARN"){
    "'$(get-date -format "dd-MMM-yy HH:mm:ss")' |'WARN' | $ErrorCode $message " | out-file $Logfile -append
  } elseif ($sev -eq "ERROR"){
    "'$(get-date -format "dd-MMM-yy HH:mm:ss")' |'ERROR'| $ErrorCode $message " | out-file $Logfile -append
    if ($PSVersionTable.PSVersion.Major -ne 5){
      $Global:MyExit = 1
      start-sleep 10
      if ($MyExit -eq 1){
        $global:LASTEXITCODE = 1
      }
    }
    if ($GlobalPsInvokeRetryCounter -ge 5){
      "'$(get-date -format "dd-MMM-yy HH:mm:ss")' |'ERROR'| 0 Global Retry Counter is greater than '5', breaking out." | out-file $Logfile -append
      break
    }
  } elseif ($sev -match "CHAPTER"){
    "" | out-file $Logfile -append
    "####################################################################" | out-file $Logfile -append
    "#                                                                  #" | out-file $Logfile -append
    "#     $message"
    if ($message -match "Task .* Completed"){
      $timespan = New-TimeSpan -Start $starttime -End $stoptime
      "#                                                                  #" | out-file $Logfile -append
      "#     Runtime took '$($timespan.days)' days, '$($timespan.hours)' hours, '$($timespan.minutes)' minutes, '$($timespan.seconds) seconds'"
      "#                                                                  #" | out-file $Logfile -append
    } elseif ($sev -match "MasterCHAPTER"){
      "#                                                                  #" | out-file $Logfile -append
      "#                                                                  #" | out-file $Logfile -append
      "#                                                                  #" | out-file $Logfile -append
      "#                                                                  #" | out-file $Logfile -append
      "# Framework Load Completed. Please follow the output below.        #" | out-file $Logfile -append
    } else {
      "#                                                                  #" | out-file $Logfile -append
    }
    "####################################################################" | out-file $Logfile -append
    "" | out-file $Logfile -append
  }
} 