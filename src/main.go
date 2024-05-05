package main

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

type accountsLoaded struct {
	accounts  []string
	maxLength int
	page      int
}

func showAccountData(id int, accounts accountsLoaded, accountDisplay *widget.Label) {
	accountDisplay.SetText(fmt.Sprintf("The accounts %s is selected", accounts.accounts[id]))
}

func main() {
	hkPasswordm := app.New()
	mainWindow := hkPasswordm.NewWindow("hk-passwordm")
	mainWindow.Resize(fyne.NewSize(860, 560))

	listAccs := accountsLoaded{
		accounts:  []string{"Account1", "Account2", "Account1", "Account2", "Account1", "Account2", "Account1", "Account2", "Account1", "Account2", "Account1", "Account2", "Account1", "Account2", "Account1", "Account2", "Account1", "Account2"},
		maxLength: 25,
		page:      1,
	}

	accountList := widget.NewList(
		func() int {
			return len(listAccs.accounts)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(listAccs.accounts[i])
		})

	accountDisplay := widget.NewLabel("")
	accountDisplay.SetText("No account currently selected!")

	accountList.OnSelected = func(id widget.ListItemID) {
		showAccountData(id, listAccs, accountDisplay)
	}

	mainGrid := container.New(layout.NewGridLayout(2), accountList, accountDisplay)
	mainWindow.SetContent(mainGrid)

	mainWindow.ShowAndRun()
}
