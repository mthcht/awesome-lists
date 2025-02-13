rule Backdoor_Win32_Wannaren_D_2147753225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wannaren.D!MTB"
        threat_id = "2147753225"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wannaren"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Backdoor returned code:" ascii //weight: 1
        $x_1_2 = "--TargetPort 445 --Protocol SMB --Architecture x64 --Function RunDLL --DllPayload" ascii //weight: 1
        $x_1_3 = "Eternalblue" ascii //weight: 1
        $x_1_4 = "Doublepulsar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

