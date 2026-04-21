rule TrojanDropper_Win32_AttackBlob_A_2147967388_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/AttackBlob.A!dha"
        threat_id = "2147967388"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "AttackBlob"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 2e cf 8f 66 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 f1 ba 87 8f 0f 19 e8 ?? ?? ?? ?? a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

