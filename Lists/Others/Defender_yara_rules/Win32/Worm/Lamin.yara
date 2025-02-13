rule Worm_Win32_Lamin_C_2147636520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Lamin.C"
        threat_id = "2147636520"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Lamin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Spread_Digsby" ascii //weight: 1
        $x_1_2 = "Spread_GoogleTalk" ascii //weight: 1
        $x_1_3 = "Ganyang Malingsia" ascii //weight: 1
        $x_1_4 = "GetExtensionName" wide //weight: 1
        $x_1_5 = "SpecialFolders" wide //weight: 1
        $x_1_6 = {04 5c ff ff 41 44 ff 6a 00 28 dc fe 01 00 5d fb 2f cc fe 04 5c ff ff 41 ac fe 6a 00 28 bc fe 03 00 5d fb 2f 9c fe}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

