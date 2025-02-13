rule Trojan_WinNT_WebHijack_KB_2147719988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/WebHijack.KB"
        threat_id = "2147719988"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "WebHijack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HTTP/1.1 302 Found" ascii //weight: 1
        $x_1_2 = "Referer: http*//*.hao123.com" ascii //weight: 1
        $x_1_3 = "\\Device\\Tcp" wide //weight: 1
        $x_1_4 = "\\Device\\Udp" wide //weight: 1
        $x_1_5 = "TransportAddress" ascii //weight: 1
        $x_1_6 = "ConnectionContext" ascii //weight: 1
        $x_3_7 = "d:\\young\\swprojects\\tdxin\\bin\\amd64\\rtdxftex_amd64.pdb" ascii //weight: 3
        $x_1_8 = "IoAttachDevice" ascii //weight: 1
        $x_1_9 = "IoCreateFileSpecifyDeviceObjectHint" ascii //weight: 1
        $x_1_10 = "PsSetLoadImageNotifyRoutine" ascii //weight: 1
        $x_1_11 = "PsGetProcessImageFileName" ascii //weight: 1
        $x_1_12 = "PsSetCreateProcessNotifyRoutine" ascii //weight: 1
        $x_1_13 = "TdiMapUserRequest" ascii //weight: 1
        $x_1_14 = "TDI.SYS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((13 of ($x_1_*))) or
            ((1 of ($x_3_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

