rule PWS_Win32_Bropaler_A_2147709855_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Bropaler.A!bit"
        threat_id = "2147709855"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Bropaler"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/newgate.php" ascii //weight: 1
        $x_1_2 = "/gate.php" ascii //weight: 1
        $x_2_3 = "\\lcx.txt" ascii //weight: 2
        $x_2_4 = "name=\"myfile\"; filename" ascii //weight: 2
        $x_2_5 = "mozillastealer" ascii //weight: 2
        $x_2_6 = "encryptedPassword" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

