rule PWS_Win32_Cabalest_A_2147611206_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Cabalest.A"
        threat_id = "2147611206"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Cabalest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 b2 68 32 01}  //weight: 1, accuracy: High
        $x_1_2 = {80 fb 61 7c 1d 80 fb 7a 7f 18 8b c6 6a 1a 99 5f f7 ff 0f be c3 2b c2 83 e8 47 99 f7 ff 80 c2 61 eb 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

