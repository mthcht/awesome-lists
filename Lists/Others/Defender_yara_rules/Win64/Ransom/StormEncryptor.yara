rule Ransom_Win64_StormEncryptor_PAA_2147975760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/StormEncryptor.PAA!MTB"
        threat_id = "2147975760"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "StormEncryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FileEncryptor-v5-hybrid" ascii //weight: 2
        $x_1_2 = "!!!README_FIRST!!!.txt" ascii //weight: 1
        $x_1_3 = "Mode 2: Multi-threaded (%d worker thread(s)). Scanning..." ascii //weight: 1
        $x_2_4 = "Storm Encryptor - Encrypt all files using Keyber Algorithm " ascii //weight: 2
        $x_1_5 = "Skipped extensions: .exe  .dll  .lnk" ascii //weight: 1
        $x_2_6 = "No -v, -sd: runs silently in background and self delete after finish" ascii //weight: 2
        $x_1_7 = "vssadmin delete shadows /All /quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

