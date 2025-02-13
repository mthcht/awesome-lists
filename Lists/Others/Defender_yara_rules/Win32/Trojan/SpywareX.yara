rule Trojan_Win32_SpywareX_CRDB_2147850806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpywareX.CRDB!MTB"
        threat_id = "2147850806"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpywareX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bVlWTV1HEwc=" ascii //weight: 1
        $x_1_2 = "encrypted_key" ascii //weight: 1
        $x_1_3 = "bWBcVQMAGQI6LkFHQUQCDCsEBWNeR11AHUcPCAo=" ascii //weight: 1
        $x_1_4 = "http://94.142.138.97/Up" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

