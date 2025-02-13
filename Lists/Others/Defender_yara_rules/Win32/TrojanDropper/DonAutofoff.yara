rule TrojanDropper_Win32_DonAutofoff_MR_2147780046_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/DonAutofoff.MR!MTB"
        threat_id = "2147780046"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "DonAutofoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SEtFWV9DVVJSRU5UX1VTRVJcU29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu" ascii //weight: 1
        $x_1_2 = "SEtFWV9MT0NBTF9NQUNISU5FXFNvZnR3YXJlXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXFJ1bg" ascii //weight: 1
        $x_1_3 = "DECRYPTDATA ( $SDATA , $G_HKEY , $CALG_USERKEY )" ascii //weight: 1
        $x_1_4 = "CryptCreateHash" ascii //weight: 1
        $x_1_5 = "CryptDeriveKey" ascii //weight: 1
        $x_1_6 = "CryptDestroyHash" ascii //weight: 1
        $x_1_7 = "CryptDestroyKey" ascii //weight: 1
        $x_1_8 = "CryptAcquireContext" ascii //weight: 1
        $x_1_9 = "FAG_DESTROYKEY" ascii //weight: 1
        $x_1_10 = "FAG_SHUTDOWN" ascii //weight: 1
        $x_1_11 = "FAG_DERIVEKEY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

