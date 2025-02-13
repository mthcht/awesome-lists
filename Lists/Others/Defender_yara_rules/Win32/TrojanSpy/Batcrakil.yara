rule TrojanSpy_Win32_Batcrakil_A_2147638551_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Batcrakil.A"
        threat_id = "2147638551"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Batcrakil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tskill AcroRd32.exe" ascii //weight: 1
        $x_1_2 = "%s<p>Capture Devices: %d</p>" ascii //weight: 1
        $x_1_3 = "<p>Computer Name: %s </p>" ascii //weight: 1
        $x_1_4 = {25 73 5c 74 65 6d 70 2e 74 78 74 [0-10] 3a 5c 73 79 73 74 65 6d 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {50 61 73 73 77 6f 72 64 [0-10] 5c 4c 6f 67 69 6e 73 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_6 = "[Enter]<br />" wide //weight: 1
        $x_1_7 = "NumP_ARROW_LFT" wide //weight: 1
        $x_2_8 = {3b cf 76 1e 8a 84 15 ?? ?? ?? ?? 8d b4 15 ?? ?? ?? ?? 8a d8 c0 eb ?? d0 ?? 0a d8 42 3b d1 88 1e 72 e2}  //weight: 2, accuracy: Low
        $x_2_9 = {76 10 80 04 3e ?? 57 46 e8 ?? ?? ?? ?? 3b f0 59 72 f0}  //weight: 2, accuracy: Low
        $x_2_10 = {6a 41 ba 41 41 41 41 59 8b c2 bf ?? ?? ?? ?? 6a 41 f3 ab}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

