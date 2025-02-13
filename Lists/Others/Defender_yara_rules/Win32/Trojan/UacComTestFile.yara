rule Trojan_Win32_UacComTestFile_A_2147691593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UacComTestFile.A"
        threat_id = "2147691593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UacComTestFile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ed8cb4ee-5511-4c3c-b62c-13ae9a525744" ascii //weight: 1
        $x_1_2 = "23f4cf5b-f396-4423-b5b0-bcf4dcb1f393" ascii //weight: 1
        $x_1_3 = "7cd40bab-3648-4511-a767-904ca4e985b7" ascii //weight: 1
        $x_1_4 = "88916dff-698a-4a74-8347-6243c43e6b38" ascii //weight: 1
        $x_1_5 = "192f2f0c-34ee-4b48-89c8-d4d6a9ff7204" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

