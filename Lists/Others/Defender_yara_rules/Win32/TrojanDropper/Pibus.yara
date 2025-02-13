rule TrojanDropper_Win32_Pibus_A_2147620560_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Pibus.A!drv"
        threat_id = "2147620560"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Pibus"
        severity = "Critical"
        info = "drv: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fa 0f 20 c0 89 44 24 08 25 ff ff fe ff 0f 22 c0 33 ff a1 ?? ?? ?? ?? 8b 00 8b 0c b8 8b 44 24 10 8d 34 b8 8b 06}  //weight: 10, accuracy: Low
        $x_10_2 = "\\Device\\Ipfilterdriver" wide //weight: 10
        $x_10_3 = "KeServiceDescriptorTable" ascii //weight: 10
        $x_1_4 = "\\driver.pdb" ascii //weight: 1
        $x_1_5 = "hooking.cpp: SST index" ascii //weight: 1
        $x_1_6 = "BogusProtocol" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

