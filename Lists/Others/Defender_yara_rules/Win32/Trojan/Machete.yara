rule Trojan_Win32_Machete_A_2147954069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Machete.A"
        threat_id = "2147954069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Machete"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe /create /ST " ascii //weight: 1
        $x_1_2 = " /SC MINUTE /MO " ascii //weight: 1
        $x_1_3 = " /TN " ascii //weight: 1
        $x_1_4 = "\\AppData\\Roaming\\Chrome\\Google" ascii //weight: 1
        $x_1_5 = " /TR " ascii //weight: 1
        $n_1_6 = "9b53e881-26a8-4973-ba2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_Machete_B_2147954070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Machete.B"
        threat_id = "2147954070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Machete"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c cd " ascii //weight: 1
        $x_1_2 = "geoip.exe" ascii //weight: 1
        $x_1_3 = " && " wide //weight: 1
        $x_1_4 = "\\AppData\\Roaming\\Chrome\\Google" ascii //weight: 1
        $x_1_5 = "> geoip.txt" ascii //weight: 1
        $n_1_6 = "9453e881-26a8-4973-ba2e-76269e901d0c" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

