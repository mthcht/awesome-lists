rule Trojan_Win32_Deepdo_17740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Deepdo"
        threat_id = "17740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Deepdo"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 73 72 69 6e 69 74 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_2 = ".cn/bin/usrinit.exe" ascii //weight: 1
        $x_1_3 = "tn=deepbar_" ascii //weight: 1
        $x_1_4 = "uid=%s&url=%s&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Deepdo_17740_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Deepdo"
        threat_id = "17740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Deepdo"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "auto.search.msn.com/response.asp" wide //weight: 10
        $x_10_2 = {46 61 76 42 6c 6f 63 6b 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 10, accuracy: High
        $x_1_3 = "tn=baidu" wide //weight: 1
        $x_1_4 = "tn=deepbar" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Deepdo_17740_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Deepdo"
        threat_id = "17740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Deepdo"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DeepdoUpdate" ascii //weight: 1
        $x_1_2 = "DeepdoFavoriteUpdate" ascii //weight: 1
        $x_1_3 = "http://toolbar.deepdo.com/download/" ascii //weight: 1
        $x_10_4 = {6f 70 65 6e 00 00 00 00 72 65 67 73 76 72 33 32 2e 65 78 65 00 00 00 00 20 22 25 73 25 73 22 20 2f 73 00 00 72 65 67 25 64 00 00 00 25 73 25 73 00 00 00 00 25 73 5c [0-16] 2e 74 6d 70 00 00 00 00 66 69 6c 65 25 64 00 00 75 72 6c 25 64 00 00 00 76 65 72 25 64 00 00 00 6d 61 69 6e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

