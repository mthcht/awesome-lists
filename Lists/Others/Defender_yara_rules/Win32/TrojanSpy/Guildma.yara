rule TrojanSpy_Win32_Guildma_A_2147741125_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Guildma.A"
        threat_id = "2147741125"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Guildma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 72 71 75 65 69 72 6f [0-2] 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

