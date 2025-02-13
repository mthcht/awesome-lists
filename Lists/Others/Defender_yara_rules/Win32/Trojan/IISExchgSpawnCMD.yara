rule Trojan_Win32_IISExchgSpawnCMD_A_2147776639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IISExchgSpawnCMD.A"
        threat_id = "2147776639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IISExchgSpawnCMD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "cmd.exe" wide //weight: 10
        $x_10_2 = "cmd /c" wide //weight: 10
        $x_10_3 = "powershell" wide //weight: 10
        $x_10_4 = "mshta.exe" wide //weight: 10
        $x_10_5 = "bitsadmin.exe" wide //weight: 10
        $x_10_6 = "msiexec.exe" wide //weight: 10
        $x_10_7 = "certutil.exe" wide //weight: 10
        $x_10_8 = "schtasks.exe" wide //weight: 10
        $x_10_9 = "wevtutil.exe" wide //weight: 10
        $x_10_10 = "whoami.exe" wide //weight: 10
        $x_10_11 = "\\net.exe" wide //weight: 10
        $x_10_12 = "reg.exe" wide //weight: 10
        $x_10_13 = "net1.exe" wide //weight: 10
        $x_10_14 = "query.exe" wide //weight: 10
        $x_10_15 = "nslookup.exe" wide //weight: 10
        $x_10_16 = "curl.exe" wide //weight: 10
        $x_10_17 = "ipconfig.exe" wide //weight: 10
        $x_10_18 = "wmic.exe" wide //weight: 10
        $x_10_19 = "wget.exe" wide //weight: 10
        $x_10_20 = "cscript.exe" wide //weight: 10
        $x_10_21 = "wscript.exe" wide //weight: 10
        $x_10_22 = "arp.exe" wide //weight: 10
        $x_10_23 = "installutil.exe" wide //weight: 10
        $x_10_24 = "netstat.exe" wide //weight: 10
        $x_10_25 = "forfiles.exe" wide //weight: 10
        $x_10_26 = "winrs.exe" wide //weight: 10
        $x_10_27 = "xcopy.exe" wide //weight: 10
        $x_10_28 = "robocopy.exe" wide //weight: 10
        $x_10_29 = "netsh.exe" wide //weight: 10
        $x_10_30 = "rundll32.exe" wide //weight: 10
        $x_10_31 = "rar.exe" wide //weight: 10
        $x_10_32 = "nltest.exe" wide //weight: 10
        $x_10_33 = "tasklist.exe" wide //weight: 10
        $x_10_34 = "7z.exe" wide //weight: 10
        $x_10_35 = "vssadmin.exe" wide //weight: 10
        $x_10_36 = "-accepteula" wide //weight: 10
        $x_10_37 = "anydesk.exe" wide //weight: 10
        $x_10_38 = "wscript.shell" wide //weight: 10
        $x_10_39 = "runas.exe" wide //weight: 10
        $x_10_40 = "ping.exe" wide //weight: 10
        $x_10_41 = "credwiz.exe" wide //weight: 10
        $x_10_42 = "qwinsta.exe" wide //weight: 10
        $x_10_43 = "systeminfo.exe" wide //weight: 10
        $x_10_44 = "quser.exe" wide //weight: 10
        $x_10_45 = "mspaint.exe" wide //weight: 10
        $x_10_46 = "calc.exe" wide //weight: 10
        $x_10_47 = {63 00 6f 00 6d 00 73 00 76 00 63 00 73 00 2e 00 64 00 6c 00 6c 00 [0-16] 6d 00 69 00 6e 00 69 00 64 00 75 00 6d 00 70 00}  //weight: 10, accuracy: Low
        $n_50_48 = "zabbix agent" wide //weight: -50
        $n_50_49 = "dump-crashreportingprocess.ps1" wide //weight: -50
        $n_50_50 = "-section:system.webserver/httperrors -existingresponse:passthrough -commit:apphost" wide //weight: -50
        $n_50_51 = "ltrestart.bat" wide //weight: -50
        $n_50_52 = "snowinventoryagent5" wide //weight: -50
        $n_50_53 = "exaedbg.cmd" wide //weight: -50
        $n_50_54 = "adp-rest-util.bat" wide //weight: -50
        $n_50_55 = "snowagent" wide //weight: -50
        $n_50_56 = "\\csc.exe" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

