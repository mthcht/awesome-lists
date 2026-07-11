rule Trojan_Win32_SnappyClient_A_2147973407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SnappyClient.A!AMTB"
        threat_id = "2147973407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SnappyClient"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "HVnc" ascii //weight: 3
        $x_3_2 = "ScreenGrabber" ascii //weight: 3
        $x_3_3 = "Keylog" ascii //weight: 3
        $x_3_4 = "BrowserCredentialsJob" ascii //weight: 3
        $x_2_5 = "CtrlAltDelSimulator" ascii //weight: 2
        $x_2_6 = "VncPassCrypt" ascii //weight: 2
        $x_2_7 = "SeDebugPrivilege" ascii //weight: 2
        $x_2_8 = "RfbClient" ascii //weight: 2
        $x_1_9 = "Archive \"%s\" failed to extract" ascii //weight: 1
        $x_1_10 = "KeylogResponseBuilder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

