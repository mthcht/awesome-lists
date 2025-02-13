rule TrojanDropper_Win32_PhantomStar_A_2147724655_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/PhantomStar.A!dha"
        threat_id = "2147724655"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "PhantomStar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b f1 57 b9 81 00 00 00 33 c0 8d bd 9e fd ff ff 66 c7 85 9c fd ff ff 00 00 f3 ab}  //weight: 10, accuracy: High
        $x_1_2 = "%s\\EnTaskLoader.exe" ascii //weight: 1
        $x_1_3 = "/task-restart" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

