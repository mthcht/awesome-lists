rule Backdoor_MSIL_Tiny_RHA_2147913347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Tiny.RHA!MTB"
        threat_id = "2147913347"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "set_UseShellExecute" ascii //weight: 1
        $x_1_2 = "c2exe.exe" ascii //weight: 1
        $x_1_3 = "Encoding" ascii //weight: 1
        $x_1_4 = "ProcessStartInfo" ascii //weight: 1
        $x_1_5 = "TcpClient" ascii //weight: 1
        $x_1_6 = "System.Net.Sockets" ascii //weight: 1
        $x_1_7 = "3.141.55.131" wide //weight: 1
        $x_1_8 = "start_upload" wide //weight: 1
        $x_1_9 = "broadcast" wide //weight: 1
        $x_1_10 = "Recieved stop message. Breaking loop" wide //weight: 1
        $x_1_11 = "Changed!" wide //weight: 1
        $x_2_12 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 30 00 00 10 00 00 00 08 00 00 00 00 00 00 3a 2e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

