rule Trojan_Win32_OysterLoader_KAA_2147912894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OysterLoader.KAA!MTB"
        threat_id = "2147912894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OysterLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ITkrfSaV-4f7KwdfnC-Ds165XU4C-lH6R9pk1" wide //weight: 2
        $x_1_2 = "Test" ascii //weight: 1
        $x_1_3 = "postman\\Desktop\\NZT\\ProjectD_cpprest\\CleanUp\\Release\\CleanUp.pdb" ascii //weight: 1
        $x_1_4 = {3b fe 72 54 8b 07 3b 45 fc 74 f2 33 c2 8b 55 fc d3 c8 8b c8 89 17 89 45 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OysterLoader_ST_2147954020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OysterLoader.ST"
        threat_id = "2147954020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OysterLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "schtasks.exe" wide //weight: 1
        $x_1_2 = "/create" wide //weight: 1
        $x_1_3 = {5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 72 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 29 16 16 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "%username%" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

