rule Trojan_Win32_ETWKeyLogger_2147759679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ETWKeyLogger!ibt"
        threat_id = "2147759679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ETWKeyLogger"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "36DA592D-E43A-4E28-AF6F-4BC57C5A11E8" ascii //weight: 1
        $x_1_2 = "C88A4EF5-D048-4013-9408-E04B7DB2814A" ascii //weight: 1
        $x_1_3 = "ETWTraceEventSource" ascii //weight: 1
        $x_1_4 = "fid_URB_TransferBufferLength" ascii //weight: 1
        $x_1_5 = "add_CancelKeyPress" ascii //weight: 1
        $x_1_6 = "isCtrlCExecuted" ascii //weight: 1
        $x_1_7 = "fid_USBPORT_URB_BULK_OR_INTERRUPT_TRANSFER" ascii //weight: 1
        $x_1_8 = "<StartDumpKeys>" ascii //weight: 1
        $x_3_9 = "USB Keylogger using Event Tracing for Windows" ascii //weight: 3
        $x_1_10 = "ignoring non-usb keyboard device: 0x{0:X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

