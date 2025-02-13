rule Trojan_MSIL_AgentWrap_AB_2147767062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AgentWrap.AB!MTB"
        threat_id = "2147767062"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentWrap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tedburke/CommandCam/master/CommandCam.exe" ascii //weight: 1
        $x_1_2 = "Trying create screenshot from camera" ascii //weight: 1
        $x_1_3 = "/LimerBoy/hackpy/master/modules/audio.zip" ascii //weight: 1
        $x_1_4 = "All files decrypted in user directory" ascii //weight: 1
        $x_1_5 = "Failed to decrypt file. Wrong password!" ascii //weight: 1
        $x_1_6 = "\\keylogs" ascii //weight: 1
        $x_1_7 = "/master/Stealer/Stealer/modules/Sodium.dll" ascii //weight: 1
        $x_1_8 = "/TelegramRAT/core/libs/AudioSwitcher.AudioApi.dll" ascii //weight: 1
        $x_1_9 = "Webcam not found!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

