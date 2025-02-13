rule TrojanDropper_MSIL_DarkNeuron_A_2147724730_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/DarkNeuron.A!dha"
        threat_id = "2147724730"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkNeuron"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "c:\\Develop\\internal\\neuron-client\\dropper-svc\\obj\\Release\\dropper-svc.pdb" ascii //weight: 20
        $x_20_2 = "c:\\Develop\\internal\\neuron-client\\dropper\\obj\\Release\\dropper.pdb" ascii //weight: 20
        $x_1_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-80] 2e 00 61 00 73 00 6d 00 78 00}  //weight: 1, accuracy: Low
        $x_1_4 = "pipe://*/Winsock2/w3svc" wide //weight: 1
        $x_1_5 = "https://*:443/W3SVC/" wide //weight: 1
        $x_1_6 = "http://*:80/W3SVC/" wide //weight: 1
        $x_1_7 = "-x86-ui." wide //weight: 1
        $x_1_8 = "8d963325-01b8-4671-8e82-d0904275ab06" wide //weight: 1
        $x_1_9 = "InstallDate" wide //weight: 1
        $x_1_10 = "ZmlyZWZveCxjaHJvbWUsb3BlcmEsYWJieSxtb3ppbGxhLGdvb2dsZSxoZXdsZXQsZXBzb24seGVyb3gscmljb2gsYWRvYmUs" wide //weight: 1
        $x_1_11 = "Y29yZWwsamF2YSxudmlkaWEscmVhbHRlayxvcmFjbGUsd2lucmFyLDd6aXAsdm13YXJlLGp1bmlwZXIsa2FzcGVyc2t5LG1j" wide //weight: 1
        $x_1_12 = "YWZlZSxzeW1hbnRlYyx5YWhvbyxvZmZpY2UsZXhjaGFuZ2UsZ29vZ2xlLGFiYnl5" wide //weight: 1
        $x_1_13 = "YWZlZSxzeW1hbnRlYyx5YWhvbyxnb29n" wide //weight: 1
        $x_1_14 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" wide //weight: 1
        $x_1_15 = "2012-10-11T13:21:17" wide //weight: 1
        $x_1_16 = "SOFTWARE\\Microsoft\\Cryptography" wide //weight: 1
        $x_1_17 = "SUBKEY - " wide //weight: 1
        $x_1_18 = " VALUENAME - " wide //weight: 1
        $x_1_19 = "\\w3wpdiag.exe" wide //weight: 1
        $x_1_20 = "cmd.exe" wide //weight: 1
        $x_1_21 = "/c w3wpdiag.exe -install" wide //weight: 1
        $x_1_22 = "/c del *.InstallLog *.InstallState" wide //weight: 1
        $x_1_23 = "inputData must be non-null" wide //weight: 1
        $x_1_24 = "\\System.Web.Helpers.dll" wide //weight: 1
        $x_1_25 = "\\Interop.TaskScheduler.dll" wide //weight: 1
        $x_1_26 = "C:\\Windows\\system32" wide //weight: 1
        $x_1_27 = "-install" wide //weight: 1
        $x_1_28 = "-uninstall" wide //weight: 1
        $x_1_29 = "$c8b14e18-6328-47b7-a03c-2941b658197e" ascii //weight: 1
        $x_1_30 = "dropper" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((15 of ($x_1_*))) or
            ((1 of ($x_20_*))) or
            (all of ($x*))
        )
}

