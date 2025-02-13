rule Trojan_Win32_Rapid_A_2147747782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rapid.A!MTB"
        threat_id = "2147747782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rapid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!DECRYPT_FILES.txt" ascii //weight: 1
        $x_1_2 = "Congratulations, you files have been encrypted." ascii //weight: 1
        $x_1_3 = "Your documents, photos, databases and other important files have been encrypted" ascii //weight: 1
        $x_1_4 = "Software\\EncryptUID" ascii //weight: 1
        $x_1_5 = "For further steps read DECRYPT_FILES.txt" ascii //weight: 1
        $x_1_6 = "}\\norapid.exe" ascii //weight: 1
        $x_1_7 = "}\\rapidrecovery.txt" ascii //weight: 1
        $x_1_8 = "/c tasklist /fi \"imagename eq MsMpEng.exe\" | find /c \"PID\" && Echo Windows Defender" ascii //weight: 1
        $x_1_9 = "/c vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_10 = "Also! At this page you will be able to restore any one file for free!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Rapid_AA_2147747823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rapid.AA!MTB"
        threat_id = "2147747823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rapid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\EncryptKeys" ascii //weight: 1
        $x_1_2 = "recovery.txt" ascii //weight: 1
        $x_1_3 = "How Recovery Files.txt" ascii //weight: 1
        $x_1_4 = "DECRYPTED" ascii //weight: 1
        $x_1_5 = "IEFMTCBZT1VSIERPQ1VNRU5UUywgUEhPVE9TLCBEQVRBQkFTRVMgQU5EIE9USEVSIElNUE9SVEFOVCBGSUxFUyBIQVZFIEJFRU4gRU5DUllQVEVEIQ0" ascii //weight: 1
        $x_1_6 = "CiBOb3RlISBEb250IGRlbGV0ZSByYW5zb213YXJlIGFuZCB0dXJuLW9uIGFueSBhbnRpdmlydXMsIGJlY2F1c2UgeW91IGNhbiBsb3NzIGFsbCB5b3VyIGZpbGVzIQ0" ascii //weight: 1
        $x_1_7 = "IFdlIHNlbmQgeW91IGZ1bGwgaW5zdHJ1Y3Rpb24gaG93IHRvIGRlY3J5cHQgYWxsIHlvdXIgZmlsZXMu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

