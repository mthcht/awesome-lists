rule Trojan_Win32_Dwinup_A_2147627175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dwinup.A"
        threat_id = "2147627175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dwinup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft.DirectMusicSynch" ascii //weight: 1
        $x_1_2 = "BC968B03-EBDE-40f7-8934-888F5EE30A5C" ascii //weight: 1
        $x_1_3 = "PartenerName" ascii //weight: 1
        $x_1_4 = {77 69 6e 75 70 64 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_5 = "Default_Page_URL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

