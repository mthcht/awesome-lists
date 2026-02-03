rule HackTool_Win64_AutoKMS_AR_2147962292_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/AutoKMS.AR!AMTB"
        threat_id = "2147962292"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "AutoKMS"
        severity = "High"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Read KMS data file version %u.%u %s" ascii //weight: 1
        $x_1_2 = "<<< Incoming KMS request" ascii //weight: 1
        $x_1_3 = "Key Management Server" ascii //weight: 1
        $x_1_4 = "KMS host current active clients : %u" ascii //weight: 1
        $x_1_5 = "Activation interval policy      : %u" ascii //weight: 1
        $x_1_6 = "KMS host Hardware ID            : %016I64X" ascii //weight: 1
        $x_1_7 = "Warning: Transfer syntax %s does not support KMS activation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

