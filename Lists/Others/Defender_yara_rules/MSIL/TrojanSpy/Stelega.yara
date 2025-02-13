rule TrojanSpy_MSIL_Stelega_AV_2147771691_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stelega.AV!MTB"
        threat_id = "2147771691"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OIEPG.exe" ascii //weight: 1
        $x_1_2 = "SetWindowsHookEx" ascii //weight: 1
        $x_1_3 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "StrReverse" ascii //weight: 1
        $x_1_6 = "OIEPG.Properties.Resources.resources" ascii //weight: 1
        $x_1_7 = "e2acb467-72ee-4e9b-950d-e2cfdb8a48d1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stelega_AVP_2147771834_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stelega.AVP!MTB"
        threat_id = "2147771834"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinForms_RecursiveFormCreate" wide //weight: 1
        $x_1_2 = "WinForms_SeeInnerException" wide //weight: 1
        $x_1_3 = "Imaginer.malheureux" wide //weight: 1
        $x_1_4 = "Qh2/JpR9UAIrLoP52wWaurKn6Ryh7DnS7hDJHoXQLB1e4QyB6F0SQBVej273oxGamcYzWr5O1X31zHH1Txpk5d98xR9UcKZe9CkIZH3A/ofGHG3m8HoA/" wide //weight: 1
        $x_1_5 = "a7c8d659-4e4c-4c4d-9d19-f975be357d54" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stelega_VPA_2147771950_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stelega.VPA!MTB"
        threat_id = "2147771950"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\RS.bat" wide //weight: 1
        $x_1_2 = "chcp 65001" wide //weight: 1
        $x_1_3 = "$6c2b7587-904d-417a-baaa-f71c860bcfd1" ascii //weight: 1
        $x_1_4 = "DGVBebida_CellClick" ascii //weight: 1
        $x_1_5 = "DGVCervezas_CellClick" ascii //weight: 1
        $x_1_6 = "MenuVirtual.FCStartC.resources" ascii //weight: 1
        $x_1_7 = "MenuVirtual.Frmcomida.resources" ascii //weight: 1
        $x_1_8 = "MenuVirtual.FrmCantidad.resources" ascii //weight: 1
        $x_1_9 = "MenuVirtual.DinerMenuForm.resources" ascii //weight: 1
        $x_1_10 = "MenuVirtual.FrmOrden.resources" ascii //weight: 1
        $x_1_11 = "MenuVirtual.FrmComentar.resources" ascii //weight: 1
        $x_1_12 = "MenuVirtual.ICustomAttributeProvider.resources" ascii //weight: 1
        $x_1_13 = "MenuVirtual.frmbebidas.resources" ascii //weight: 1
        $x_1_14 = "MenuVirtual.Resources.resources" ascii //weight: 1
        $x_1_15 = "MenuVirtual.Opciones.resources" ascii //weight: 1
        $x_1_16 = "MenuVirtual.FrmPostres.resources" ascii //weight: 1
        $x_1_17 = "MenuVirtual.PN_Menu.resources" ascii //weight: 1
        $x_1_18 = "MenuVirtual.FrmMenu.resources" ascii //weight: 1
        $x_1_19 = "MenuVirtual.BtnMenu.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

