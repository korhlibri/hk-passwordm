package main

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

/*
#cgo LDFLAGS: -L../target/release -lhk_passwordm
#include "link.h"
*/
import "C"

type accountsLoaded struct {
	maxLength int
	accounts  []string
	page      int
}

type currentAccount struct {
	account  string
	username string
	password string
}

func showAccountData(id int, accounts accountsLoaded, accountDisplay *widget.Label, accountUsername *widget.Entry, accountPassword *widget.Entry, accountGrid *fyne.Container) {
	accountDisplay.SetText(fmt.Sprintf(accounts.accounts[id]))
	accountUsername.SetText("Test")
	accountPassword.SetText("Test")
	accountGrid.Hidden = false
}

func main() {
	hkPasswordm := app.New()
	mainWindow := hkPasswordm.NewWindow("hk-passwordm")
	mainWindow.SetMaster()
	mainWindow.Resize(fyne.NewSize(600, 400))

	menu := fyne.NewMainMenu(
		fyne.NewMenu("File",
			fyne.NewMenuItem("New Password File", func() {}),
			fyne.NewMenuItem("Open Password File", func() {}),
		),
		fyne.NewMenu("About",
			fyne.NewMenuItem("License", func() {}),
			fyne.NewMenuItem("Used Dependency Licenses", func() {}),
		),
	)

	mainWindow.SetMainMenu(menu)

	listAccs := accountsLoaded{
		accounts:  []string{"Account1", "Account2", "Account1", "Account2", "Account1", "Account2", "Account1", "Account2", "Account1", "Account2", "Account1", "Account2", "Account1", "Account2", "Account1", "Account2", "Account1", "Account2"},
		maxLength: 25,
		page:      1,
	}

	// top left (pagination and adding accounts)
	pastPage := widget.NewButton("<", func() {})
	setPage := widget.NewEntry()
	nextPage := widget.NewButton(">", func() {})

	loadingBar := widget.NewProgressBarInfinite()
	loadingBar.Hide()

	addAccount := widget.NewButton("+", func() {})

	pagination := container.New(layout.NewHBoxLayout(), pastPage, setPage, nextPage)
	topLeft := container.NewBorder(nil, nil, pagination, addAccount, loadingBar)

	// top right (searching for specific account)
	searchField := widget.NewEntry()
	searchButton := widget.NewButton("", func() {})
	searchButton.SetIcon(theme.SearchIcon())

	topRight := container.NewBorder(nil, nil, nil, searchButton, searchField)

	// bottom left (account listing)
	boundAccounts := binding.BindStringList(&listAccs.accounts)

	accountList := widget.NewListWithData(boundAccounts,
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(i binding.DataItem, o fyne.CanvasObject) {
			o.(*widget.Label).Bind(i.(binding.String))
		},
	)

	leftItems := container.NewBorder(topLeft, nil, nil, nil, accountList)

	// bottom right (selected account details)
	accountDisplay := widget.NewLabel("No account currently selected!")
	accountUsername := widget.NewEntry()
	accountPassword := widget.NewPasswordEntry()

	accountModify := widget.NewButton("Modify Account Data", func() {})
	accountDelete := widget.NewButton("Delete Account", func() {})
	accountDetailsGrid := container.New(
		layout.NewGridLayout(2),
		widget.NewLabel("Account: "),
		accountDisplay, widget.NewLabel("Username: "),
		accountUsername, widget.NewLabel("Password: "),
		accountPassword,
	)

	accountDetailsWithActions := container.New(layout.NewVBoxLayout(), accountDetailsGrid, accountModify, accountDelete)
	accountDetailsWithActions.Hidden = true

	accountList.OnSelected = func(id widget.ListItemID) {
		showAccountData(id, listAccs, accountDisplay, accountUsername, accountPassword, accountDetailsWithActions)
	}

	rightItems := container.New(layout.NewVBoxLayout(), topRight, layout.NewSpacer(), accountDetailsWithActions, layout.NewSpacer())

	mainGrid := container.New(layout.NewAdaptiveGridLayout(2), leftItems, rightItems)
	mainWindow.SetContent(mainGrid)

	// mainWindow.ShowAndRun()
}
