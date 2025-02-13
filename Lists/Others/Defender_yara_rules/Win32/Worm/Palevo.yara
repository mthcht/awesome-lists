rule Worm_Win32_Palevo_2147641581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Palevo"
        threat_id = "2147641581"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Palevo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3a 52 45 44 4f 0a 64 65 6c 20 25 30 0a 65 78 69 74}  //weight: 1, accuracy: High
        $x_1_2 = "/ldr/client.php?family=bank" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

