rule HackTool_Win32_ZorHeard_A_2147894764_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/ZorHeard.A!dha"
        threat_id = "2147894764"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ZorHeard"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "300"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "iieunh523Xsaw" wide //weight: 100
        $x_100_2 = "open new Type waveaudio Alias recsound" wide //weight: 100
        $x_100_3 = "set recsound bitspersample 8 channels 1 samplespersec 11025" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

