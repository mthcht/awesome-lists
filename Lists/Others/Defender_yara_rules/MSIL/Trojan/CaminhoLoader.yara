rule Trojan_MSIL_CaminhoLoader_AASB_2147964733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CaminhoLoader.AASB!MTB"
        threat_id = "2147964733"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CaminhoLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "caminho" ascii //weight: 5
        $x_1_2 = "payloadBuffer" ascii //weight: 1
        $x_1_3 = "vmDetectionName" ascii //weight: 1
        $x_1_4 = "uacPayloadUrl" ascii //weight: 1
        $x_1_5 = "encodedUrlPayload" ascii //weight: 1
        $x_1_6 = "DsCrackNames" ascii //weight: 1
        $x_1_7 = "AllowingStartOnRemoteAppSession" ascii //weight: 1
        $x_1_8 = "set_LogonType" ascii //weight: 1
        $x_1_9 = "set_UserPassword" ascii //weight: 1
        $x_1_10 = "set_UserAccountDomain" ascii //weight: 1
        $x_1_11 = "Microsoft.Win32.TaskScheduler.Trigger>.Add" ascii //weight: 1
        $x_1_12 = "is tampered." ascii //weight: 1
        $x_1_13 = "Debugger Detected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

