rule Trojan_MSIL_Nomercy_SYD_2147827846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nomercy.SYD!MTB"
        threat_id = "2147827846"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nomercy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NoMercy-v1.0" wide //weight: 1
        $x_1_2 = "WindowsKernelDrivers.exe" wide //weight: 1
        $x_1_3 = "six-clowns-sing-103-119-240-166.loca.lt" wide //weight: 1
        $x_1_4 = "api.ipify.org" wide //weight: 1
        $x_1_5 = "HttpWebRequest" ascii //weight: 1
        $x_1_6 = "HttpWebResponse" ascii //weight: 1
        $x_1_7 = "GetResponse" ascii //weight: 1
        $x_1_8 = "PostUID" ascii //weight: 1
        $x_1_9 = "/a?uid=" wide //weight: 1
        $x_1_10 = "&version=" wide //weight: 1
        $x_1_11 = "UID and Version sent" wide //weight: 1
        $x_1_12 = "CollectInformation_CLI" ascii //weight: 1
        $x_1_13 = "whoami /all info:" wide //weight: 1
        $x_1_14 = "arp -a info:" wide //weight: 1
        $x_1_15 = "ipconfig /all info:" wide //weight: 1
        $x_1_16 = "net view /all info:" wide //weight: 1
        $x_1_17 = "netstat -nao info: " wide //weight: 1
        $x_1_18 = "route print info:" wide //weight: 1
        $x_1_19 = "systeminfo info:" wide //weight: 1
        $x_1_20 = "Took webcam snapshot" wide //weight: 1
        $x_1_21 = "Sending webcam snapshot..." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

