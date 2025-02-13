rule Trojan_Win64_AVBurner_RPX_2147835184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AVBurner.RPX!MTB"
        threat_id = "2147835184"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AVBurner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\\\.\\RTCORE64" wide //weight: 10
        $x_1_2 = "ntoskrnl.exe" wide //weight: 1
        $x_1_3 = "testxxxx" wide //weight: 1
        $x_1_4 = "PsSetCreateProcessNotifyRoutine" ascii //weight: 1
        $x_1_5 = "IoCreateDriver" ascii //weight: 1
        $x_1_6 = "PsRemoveLoadImageNotifyRoutine" ascii //weight: 1
        $x_1_7 = "NtFindAtom" ascii //weight: 1
        $x_1_8 = "KeRegisterProcessorChangeCallback" ascii //weight: 1
        $x_1_9 = "ImpersonateNamedPipeClient" ascii //weight: 1
        $x_1_10 = "wsprintfW" ascii //weight: 1
        $x_1_11 = "K32GetDeviceDriverFileNameW" ascii //weight: 1
        $x_1_12 = "WaitForSingleObject" ascii //weight: 1
        $x_10_13 = {41 b9 30 00 00 00 48 89 44 24 20 ba 48 20 00 80 4c 89 65 cf 49 8b cf 4c 89 65 df f3 0f 7f 45 eb 44 89 65 fb 48 89 7d d7 c7 45 e7 04 00 00 00 ff 15}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

