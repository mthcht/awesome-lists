rule Trojan_Win32_HijackExchgServer_A_2147841738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HijackExchgServer.A"
        threat_id = "2147841738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HijackExchgServer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cmd.exe" wide //weight: 10
        $x_10_2 = "cmd /c" wide //weight: 10
        $x_10_3 = "powershell.exe" wide //weight: 10
        $x_10_4 = "whoami.exe" wide //weight: 10
        $x_10_5 = "\\net.exe" wide //weight: 10
        $x_10_6 = "net1.exe" wide //weight: 10
        $x_10_7 = "ipconfig.exe" wide //weight: 10
        $x_10_8 = "ping.exe" wide //weight: 10
        $n_50_9 = "zabbix agent" wide //weight: -50
        $n_50_10 = "dump-crashreportingprocess.ps1" wide //weight: -50
        $n_50_11 = "-section:system.webserver/httperrors -existingresponse:passthrough -commit:apphost" wide //weight: -50
        $n_50_12 = "ltrestart.bat" wide //weight: -50
        $n_50_13 = "snowinventoryagent5" wide //weight: -50
        $n_50_14 = "exaedbg.cmd" wide //weight: -50
        $n_50_15 = "adp-rest-util.bat" wide //weight: -50
        $n_50_16 = "snowagent" wide //weight: -50
        $n_50_17 = "-version 5.1 -s -nologo -noprofile" wide //weight: -50
        $n_50_18 = "\\temp\\tmp_*." wide //weight: -50
        $n_50_19 = "\\csc.exe" wide //weight: -50
        $n_50_20 = "-tenantid " wide //weight: -50
        $n_50_21 = "-newAlias" wide //weight: -50
        $n_50_22 = "-removeAlias" wide //weight: -50
        $n_50_23 = "SaviyntApp" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_HijackExchgServer_AB_2147849304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HijackExchgServer.AB"
        threat_id = "2147849304"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HijackExchgServer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mshta.exe" wide //weight: 10
        $x_10_2 = "bitsadmin.exe" wide //weight: 10
        $x_10_3 = "wmic.exe" wide //weight: 10
        $x_10_4 = "cscript.exe" wide //weight: 10
        $x_10_5 = "wscript.exe" wide //weight: 10
        $x_10_6 = "rundll32.exe" wide //weight: 10
        $x_10_7 = "-accepteula" wide //weight: 10
        $x_10_8 = "reg.exe" wide //weight: 10
        $n_50_9 = "zabbix agent" wide //weight: -50
        $n_50_10 = "dump-crashreportingprocess.ps1" wide //weight: -50
        $n_50_11 = "-section:system.webserver/httperrors -existingresponse:passthrough -commit:apphost" wide //weight: -50
        $n_50_12 = "ltrestart.bat" wide //weight: -50
        $n_50_13 = "snowinventoryagent5" wide //weight: -50
        $n_50_14 = "exaedbg.cmd" wide //weight: -50
        $n_50_15 = "adp-rest-util.bat" wide //weight: -50
        $n_50_16 = "snowagent" wide //weight: -50
        $n_50_17 = "-version 5.1 -s -nologo -noprofile" wide //weight: -50
        $n_50_18 = "\\temp\\tmp_*." wide //weight: -50
        $n_50_19 = "\\csc.exe" wide //weight: -50
        $n_50_20 = "-tenantid " wide //weight: -50
        $n_50_21 = "wmic useraccount list brief" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

