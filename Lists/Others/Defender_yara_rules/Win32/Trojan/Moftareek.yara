rule Trojan_Win32_Moftareek_B_2147805728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Moftareek.B"
        threat_id = "2147805728"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Moftareek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Documents\\dev\\wizard_spider\\Resources\\Emotet\\EmotetClientDLL\\Release\\EmotetClientDLL.pdb" ascii //weight: 1
        $x_1_2 = "executeLatMovementCmd@@YA_NPAVEmotetComms@@" ascii //weight: 1
        $x_1_3 = "sendRequest@EmotetComms@@" ascii //weight: 1
        $x_1_4 = "successfully set task output" ascii //weight: 1
        $x_1_5 = "\\Ygyhlqt\\Bx5jfmo\\R43H.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

