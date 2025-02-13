rule Trojan_MSIL_Stealbit_STA_2147797824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealbit.STA"
        threat_id = "2147797824"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealbit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Connecting to host..." ascii //weight: 1
        $x_1_2 = "| Stop-Process -Force" ascii //weight: 1
        $x_1_3 = "Remove-Item -Path $path" ascii //weight: 1
        $x_1_4 = "SSH-2.0-Renci.SshNet.SshClient." ascii //weight: 1
        $x_1_5 = "scp -r -p -d -t {0}" ascii //weight: 1
        $x_2_6 = "165.22.84.147" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

