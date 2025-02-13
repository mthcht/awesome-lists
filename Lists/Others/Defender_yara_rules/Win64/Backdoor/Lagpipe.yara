rule Backdoor_Win64_Lagpipe_A_2147834812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Lagpipe.A!dha"
        threat_id = "2147834812"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Lagpipe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[+] RpcRemoteFindFirstPrinterChangeNotificationEx Error %d" wide //weight: 1
        $x_1_2 = "[+] RpcOpenPrinter Error %d" wide //weight: 1
        $x_1_3 = "[-] A privilege is missing:" wide //weight: 1
        $x_1_4 = "\\\\.\\pipe\\%ws\\pipe\\spoolss" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

