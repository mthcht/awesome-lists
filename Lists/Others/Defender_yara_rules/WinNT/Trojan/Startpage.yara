rule Trojan_WinNT_Startpage_B_2147597993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Startpage.B"
        threat_id = "2147597993"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "127.0.0.1  scan.kingsoft.com" ascii //weight: 1
        $x_1_2 = "127.0.0.1  update.rising.com.cn" ascii //weight: 1
        $x_1_3 = "127.0.0.1  download.rising.com.cn" ascii //weight: 1
        $x_1_4 = ".kaspersky-labs.com" ascii //weight: 1
        $x_1_5 = "PsCreateSystemThread" ascii //weight: 1
        $x_1_6 = "PsLookupProcessByProcessId" ascii //weight: 1
        $x_1_7 = "ObReferenceObjectByHandle" ascii //weight: 1
        $x_1_8 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_9 = "PsSetCreateProcessNotifyRoutine" ascii //weight: 1
        $x_1_10 = "ntoskrnl.exe" ascii //weight: 1
        $x_1_11 = "Start Page" wide //weight: 1
        $x_1_12 = "\\Software\\Microsoft\\Internet Explorer\\Main" wide //weight: 1
        $x_1_13 = "\\SystemRoot\\system32\\drivers\\etc\\hosts" wide //weight: 1
        $x_1_14 = "\\DosDevices\\LocalSystemX" wide //weight: 1
        $x_1_15 = "\\Device\\LocalSystemX" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (13 of ($x*))
}

