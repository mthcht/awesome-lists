rule TrojanProxy_Win32_Zolpiq_A_2147645937_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Zolpiq.A"
        threat_id = "2147645937"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Zolpiq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msimage.dat" ascii //weight: 1
        $x_1_2 = {68 3f 00 0f 00 56 56 ff d0 3b c6 75 04 33 c0 5e c3 68 ff 01 0f 00 ff 74 24 0c 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Zolpiq_A_2147645937_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Zolpiq.A"
        threat_id = "2147645937"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Zolpiq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QWT /WERrchAn=" ascii //weight: 1
        $x_1_2 = "SharkConnect...%s:%d" ascii //weight: 1
        $x_1_3 = "Content-Disposition: form-data; name=\"Submit\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

