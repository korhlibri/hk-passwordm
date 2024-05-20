package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/crypto/pbkdf2"
)

/*
#cgo LDFLAGS: -L../target/release -lhk_passwordm
#include "link.h"
*/
import "C"

type AccountsLoaded struct {
	maxLength int
	accounts  []string
	page      int
}

type MessageAndError struct {
	message *C.char
	err     C.int
}

var listAccs = AccountsLoaded{
	accounts:  []string{},
	maxLength: 25,
	page:      1,
}

var filelocation string
var header []string
var key []byte

func updateListAccs(accountList binding.ExternalStringList) {
	lowerBound := (listAccs.page-1)*listAccs.maxLength + 1
	upperBound := (listAccs.page-1)*listAccs.maxLength + listAccs.maxLength + 1
	headerLength := len(header)
	if headerLength < lowerBound {
		listAccs.accounts = []string{}
	} else if headerLength-lowerBound < upperBound {
		listAccs.accounts = header[lowerBound:]
	} else {
		listAccs.accounts = header[lowerBound:upperBound]
	}
	accountList.Reload()
}

func derivePassword(password string) []byte {
	return pbkdf2.Key([]byte(password), []byte("E7xtlY9rHf"), 4096, 32, sha256.New)
}

func displayErrorDialog(err int, parent fyne.Window) {
	dialog.ShowInformation("Error", fmt.Sprintf("An error has occured. Error code : %d", err), parent)
}

func getFileHeader(fileLocation string) int {
	header_error := C.read_message_extern(C.CString(fileLocation[7:]), C.CString(string(key)), 0)
	if int(header_error.err) != 0 {
		return int(header_error.err)
	} else {
		temp_result := header_error.message
		header = strings.Split(C.GoString(temp_result), "|")
		C.deallocate_cstring(temp_result)
		return 0
	}
}

func getKeyWindow(parent fyne.Window, fileLocation string) {
	passwordField := widget.NewPasswordEntry()
	passwordFormItem := widget.NewFormItem("Enter Password :", passwordField)
	passwordForm := dialog.NewForm("Password Entry", "Confirm Password for File", "Cancel", []*widget.FormItem{passwordFormItem}, func(passed bool) {
		if passwordField.Text != "" {
			password := derivePassword(passwordField.Text)
			err := int(C.create_password_file(C.CString(fileLocation[7:]), C.CString(string(password))))
			if err != 0 {
				displayErrorDialog(err, parent)
			} else {
				key = password
				err := getFileHeader(fileLocation)
				if err != 0 {
					displayErrorDialog(err, parent)
				} else {
					dialog.ShowInformation("Success", "File created and loaded successfully", parent)
					filelocation = fileLocation
				}
			}
		} else {
			dialog.ShowInformation("Error", "You need to input a password", parent)
		}
	}, parent)
	passwordForm.Show()
}

func newPasswordFile(parent fyne.Window) {
	newFileDialog := dialog.NewFileSave(func(write fyne.URIWriteCloser, err error) {
		if err != nil || write == nil {
			return
		} else {
			getKeyWindow(parent, write.URI().String())
		}
	}, parent)
	newFileDialog.SetFileName("passwords.hkpswd")
	newFileDialog.Show()
}

func replaceNewFileWithOld() int {
	err := os.Rename(fmt.Sprintf("%s.new", filelocation[7:]), filelocation[7:])
	if err != nil {
		return 1
	} else {
		return 0
	}
}

func showAccountData(id int, accounts AccountsLoaded, accountDisplay *widget.Label, accountUsername *widget.Entry, accountPassword *widget.Entry, accountGrid *fyne.Container) {
	accountDisplay.SetText(fmt.Sprintf(accounts.accounts[id]))
	accountUsername.SetText("Test")
	accountPassword.SetText("Test")
	accountGrid.Hidden = false
}

func addAccount(parent fyne.Window, accountList binding.ExternalStringList) {
	if filelocation == "" {
		dialog.ShowInformation("Error", "You need to load an account file first. Go to File and create a new password file or open an existing one", parent)
	} else {
		accountField := widget.NewEntry()
		accountFormItem := widget.NewFormItem("Enter Account or Website :", accountField)

		usernameField := widget.NewEntry()
		usernameFormItem := widget.NewFormItem("Enter Username :", usernameField)

		passwordField := widget.NewPasswordEntry()
		passwordFormItem := widget.NewFormItem("Enter Password :", passwordField)
		passwordForm := dialog.NewForm("Password Entry", "Confirm Password for File", "Cancel", []*widget.FormItem{accountFormItem, usernameFormItem, passwordFormItem}, func(passed bool) {
			if accountField.Text != "" || usernameField.Text != "" || passwordField.Text != "" {
				err := int(C.add_account(C.CString(filelocation[7:]), C.CString(string(key)), C.CString(accountField.Text), C.CString(usernameField.Text), C.CString(passwordField.Text)))
				if err != 0 {
					displayErrorDialog(err, parent)
				} else {
					err := replaceNewFileWithOld()
					if err != 0 {
						dialog.ShowInformation("Error", "There was an error applying changes to the old file", parent)
					} else {
						err := getFileHeader(filelocation)
						if err != 0 {
							displayErrorDialog(err, parent)
						} else {
							updateListAccs(accountList)
							dialog.ShowInformation("Success", "Account added successfully", parent)
						}
					}
				}
			} else {
				dialog.ShowInformation("Error", "All fields are required to add an account", parent)
			}
		}, parent)
		passwordForm.Show()
	}
}

func main() {
	hkPasswordm := app.New()
	mainWindow := hkPasswordm.NewWindow("hk-passwordm")
	mainWindow.SetMaster()
	mainWindow.Resize(fyne.NewSize(600, 400))

	menu := fyne.NewMainMenu(
		fyne.NewMenu("File",
			fyne.NewMenuItem("New Password File", func() { newPasswordFile(mainWindow) }),
			fyne.NewMenuItem("Open Password File", func() {}),
		),
		fyne.NewMenu("About",
			fyne.NewMenuItem("License", func() {}),
			fyne.NewMenuItem("Used Dependency Licenses", func() {}),
		),
	)

	mainWindow.SetMainMenu(menu)

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

	// top left (pagination and adding accounts)
	pastPage := widget.NewButton("<", func() {})
	setPage := widget.NewEntry()
	nextPage := widget.NewButton(">", func() {})

	loadingBar := widget.NewProgressBarInfinite()
	loadingBar.Hide()

	addAccount := widget.NewButton("+", func() { addAccount(mainWindow, boundAccounts) })

	pagination := container.New(layout.NewHBoxLayout(), pastPage, setPage, nextPage)

	topLeft := container.NewBorder(nil, nil, pagination, addAccount, loadingBar)

	// top right (searching for specific account)
	searchField := widget.NewEntry()
	searchButton := widget.NewButton("", func() {})
	searchButton.SetIcon(theme.SearchIcon())

	topRight := container.NewBorder(nil, nil, nil, searchButton, searchField)

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

	mainWindow.ShowAndRun()
}
