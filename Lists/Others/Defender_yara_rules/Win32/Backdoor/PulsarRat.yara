rule Backdoor_Win32_PulsarRat_AR_2147964708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PulsarRat.AR!AMTB"
        threat_id = "2147964708"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PulsarRat"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Pulsar.Common.Messages.Monitoring.Clipboard" ascii //weight: 1
        $x_1_2 = "Pulsar.Common.Messages.Administration.RemoteShell" ascii //weight: 1
        $x_1_3 = "Pulsar.Common.Messages.Monitoring.KeyLogger" ascii //weight: 1
        $x_1_4 = "Pulsar.Common.Messages.Monitoring.Passwords" ascii //weight: 1
        $x_1_5 = "GetKeyloggerLogsDirectory" ascii //weight: 1
        $x_1_6 = "set_FakeAppData" ascii //weight: 1
        $x_1_7 = "IKeyboardMouseEvents" ascii //weight: 1
        $x_1_8 = "_screenCapture" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

