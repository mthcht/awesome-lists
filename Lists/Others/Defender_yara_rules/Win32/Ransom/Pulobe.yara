rule Ransom_Win32_Pulobe_A_2147719768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Pulobe.A"
        threat_id = "2147719768"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Pulobe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[MELT][TASKNAME]" ascii //weight: 1
        $x_1_2 = "Your files are Encrypted!" ascii //weight: 1
        $x_1_3 = "To buy the decryptor, you must pay the cost of:" ascii //weight: 1
        $x_1_4 = "mshta.exe \"javascript:o=new ActiveXObject('WScript.Shell');setInterval(function(){try{o.RegWrite('HKCU\\\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

