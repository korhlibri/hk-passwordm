// hk-passwordm - Simple password manager using Flutter for GUI and Rust
// Copyright (C) 2024 Hlib Korzhynskyy
//
// This program is free software: you can redistribute it and/or modify it under the terms of
// the GNU General Public License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with this
// program. If not, see <https://www.gnu.org/licenses/>.

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

	_ "embed"
)

/*
#cgo LDFLAGS: -L../target/release -lhk_passwordm
#include "link.h"
*/
import "C"

//go:embed license.txt
var license string

//go:embed dependency_licenses.txt
var dependency_licenses string

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
var filter bool = false
var header_filter []string = []string{"HK PASSWORD MANAGER FILE"}
var header_index []int
var key []byte

func updateListAccs(accountList binding.ExternalStringList) {
	lowerBound := (listAccs.page-1)*listAccs.maxLength + 1
	upperBound := (listAccs.page-1)*listAccs.maxLength + listAccs.maxLength + 1
	var usedHeader []string
	if filter {
		usedHeader = header_filter
	} else {
		usedHeader = header
	}
	headerLength := len(usedHeader)
	if headerLength < lowerBound {
		listAccs.accounts = nil
	} else if headerLength-lowerBound < upperBound {
		listAccs.accounts = usedHeader[lowerBound:]
	} else {
		listAccs.accounts = usedHeader[lowerBound:upperBound]
	}
	accountList.Reload()
}

func derivePassword(password string) []byte {
	return pbkdf2.Key([]byte(password), []byte("E7xtlY9rHf"), 4096, 32, sha256.New)
}

func displayErrorDialog(err int, parent fyne.Window) {
	dialog.ShowInformation("Error", fmt.Sprintf("An error has occured. Error code : %d", err), parent)
}

func getFileHeader(fileLocation string, keyToUse []byte) int {
	header_error := C.read_message_extern(C.CString(fileLocation[7:]), C.CString(string(keyToUse)), 0)
	if int(header_error.err) != 0 {
		return int(header_error.err)
	} else {
		temp_result := header_error.message
		header = strings.Split(C.GoString(temp_result), "|")
		C.deallocate_cstring(temp_result)
		return 0
	}
}

func getKeyWindow(parent fyne.Window, fileLocation string, accountList binding.ExternalStringList, op int) {
	passwordField := widget.NewPasswordEntry()
	passwordFormItem := widget.NewFormItem("Enter Password :", passwordField)
	passwordForm := dialog.NewForm("Password Entry", "Confirm Password for File", "Cancel", []*widget.FormItem{passwordFormItem}, func(passed bool) {
		if passwordField.Text != "" {
			password := derivePassword(passwordField.Text)
			if op == 0 {
				err := int(C.create_password_file(C.CString(fileLocation[7:]), C.CString(string(password))))
				if err != 0 {
					displayErrorDialog(err, parent)
				} else {
					keytemp := password
					err := getFileHeader(fileLocation, keytemp)
					if err != 0 {
						displayErrorDialog(err, parent)
					} else {
						key = keytemp
						dialog.ShowInformation("Success", "File created and loaded successfully", parent)
						filelocation = fileLocation
						updateListAccs(accountList)
					}
				}
			} else if op == 1 {
				keytemp := password
				err := getFileHeader(fileLocation, keytemp)
				if err != 0 {
					displayErrorDialog(err, parent)
				} else {
					key = keytemp
					dialog.ShowInformation("Success", "File loaded successfully", parent)
					filelocation = fileLocation
					updateListAccs(accountList)
				}
			}
		} else {
			dialog.ShowInformation("Error", "You need to input a password", parent)
		}
	}, parent)
	passwordForm.Show()
}

func newPasswordFile(parent fyne.Window, accountList binding.ExternalStringList) {
	newFileDialog := dialog.NewFileSave(func(write fyne.URIWriteCloser, err error) {
		if err != nil || write == nil {
			return
		} else {
			getKeyWindow(parent, write.URI().String(), accountList, 0)
		}
	}, parent)
	newFileDialog.SetFileName("passwords.hkpswd")
	newFileDialog.Show()
}

func openPasswordFile(parent fyne.Window, accountList binding.ExternalStringList) {
	openFileDialog := dialog.NewFileOpen(func(read fyne.URIReadCloser, err error) {
		if err != nil || read == nil {
			return
		} else {
			getKeyWindow(parent, read.URI().String(), accountList, 1)
		}
	}, parent)
	openFileDialog.Show()
}

func replaceNewFileWithOld() int {
	err := os.Rename(fmt.Sprintf("%s.new", filelocation[7:]), filelocation[7:])
	if err != nil {
		return 1
	} else {
		return 0
	}
}

func showAccountData(parent fyne.Window, id int, accounts AccountsLoaded, accountDisplay *widget.Label, accountUsername *widget.Entry, accountPassword *widget.Entry, accountGrid *fyne.Container) {
	list_id := id
	if filter {
		id = header_index[id]
	} else {
		id = list_id + 1
	}
	message_error := C.read_message_extern(C.CString(filelocation[7:]), C.CString(string(key)), C.int(id))
	if int(message_error.err) != 0 {
		displayErrorDialog(int(message_error.err), parent)
	} else {
		temp_result := message_error.message
		message := strings.Split(C.GoString(temp_result), "|")
		C.deallocate_cstring(temp_result)
		accountDisplay.SetText(fmt.Sprintf(accounts.accounts[list_id]))
		accountUsername.SetText(message[1])
		accountPassword.SetText(message[2])
		accountGrid.Hidden = false
	}
}

func addAccount(parent fyne.Window, accountList binding.ExternalStringList) {
	if filelocation == "" {
		dialog.ShowInformation("Error", "You need to load an account file first through the File menu.", parent)
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
						err := getFileHeader(filelocation, key)
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

func modifyAccount(parent fyne.Window, account string, username string, password string) {
	err := int(C.modify_account(C.CString(filelocation[7:]), C.CString(string(key)), C.CString(account), C.CString(username), C.CString(password)))
	if err != 0 {
		displayErrorDialog(err, parent)
	} else {
		err := replaceNewFileWithOld()
		if err != 0 {
			dialog.ShowInformation("Error", "There was an error applying changes to the old file", parent)
		} else {
			err := getFileHeader(filelocation, key)
			if err != 0 {
				displayErrorDialog(err, parent)
			} else {
				dialog.ShowInformation("Success", "Account modified successfully", parent)
			}
		}
	}
}

func deleteAccount(parent fyne.Window, accountList binding.ExternalStringList, account string, listWidget *widget.List) {
	confirmDialog := dialog.NewConfirm("Delete Account", "Are you sure you would like to delete this account?", func(confirm bool) {
		if confirm {
			err := int(C.delete_account(C.CString(filelocation[7:]), C.CString(string(key)), C.CString(account)))
			if err != 0 {
				displayErrorDialog(err, parent)
			} else {
				err := replaceNewFileWithOld()
				if err != 0 {
					dialog.ShowInformation("Error", "There was an error applying changes to the old file", parent)
				} else {
					err := getFileHeader(filelocation, key)
					if err != 0 {
						displayErrorDialog(err, parent)
					} else {
						listWidget.UnselectAll()
						updateListAccs(accountList)
						dialog.ShowInformation("Success", "Account modified successfully", parent)
					}
				}
			}
		}
	}, parent)
	confirmDialog.Show()
}

func pageLeft(accountPage binding.ExternalInt, accountList binding.ExternalStringList) {
	if listAccs.page <= 1 {
		listAccs.page = 1
	} else {
		listAccs.page -= 1
	}
	accountPage.Reload()
	updateListAccs(accountList)
}

func pageRight(accountPage binding.ExternalInt, accountList binding.ExternalStringList) {
	listAccs.page += 1
	accountPage.Reload()
	updateListAccs(accountList)
}

func searchAccount(parent fyne.Window, accountList binding.ExternalStringList, searchField *widget.Entry, listWidget *widget.List) {
	if filelocation == "" {
		dialog.ShowInformation("Error", "You need to load an account file first through the File menu.", parent)
	} else {
		listWidget.UnselectAll()
		if searchField.Text == "" {
			filter = false
		} else {
			filter = true
			header_filter = []string{"HK PASSWORD MANAGER FILE"}
			header_index = nil
			for i, v := range header {
				if strings.Contains(v, searchField.Text) {
					header_filter = append(header_filter, v)
					header_index = append(header_index, i)
				}
			}
		}
		updateListAccs(accountList)
	}
}

func displayLicense(hkPasswordm fyne.App) {
	licenseWindow := hkPasswordm.NewWindow("License")

	licenseEntry := widget.NewEntry()
	licenseEntry.SetText(license)
	licenseEntry.MultiLine = true
	licenseEntry.Disabled()

	content := container.NewBorder(nil, nil, nil, nil, licenseEntry)

	licenseWindow.SetContent(content)
	licenseWindow.Resize(fyne.NewSize(620, 500))
	licenseWindow.Show()
}

func displayDependencyLicences(hkPasswordm fyne.App) {
	licenseWindow := hkPasswordm.NewWindow("Dependency Licenses")

	licenseEntry := widget.NewEntry()
	licenseEntry.SetText(dependency_licenses)
	licenseEntry.MultiLine = true
	licenseEntry.Disabled()

	content := container.NewBorder(nil, nil, nil, nil, licenseEntry)

	licenseWindow.SetContent(content)
	licenseWindow.Resize(fyne.NewSize(650, 500))
	licenseWindow.Show()
}

func main() {
	hkPasswordm := app.New()
	mainWindow := hkPasswordm.NewWindow("hk-passwordm")
	mainWindow.SetMaster()
	mainWindow.Resize(fyne.NewSize(640, 420))

	boundAccounts := binding.BindStringList(&listAccs.accounts)
	boundPage := binding.BindInt(&listAccs.page)

	menu := fyne.NewMainMenu(
		fyne.NewMenu("File",
			fyne.NewMenuItem("New Password File", func() { newPasswordFile(mainWindow, boundAccounts) }),
			fyne.NewMenuItem("Open Password File", func() { openPasswordFile(mainWindow, boundAccounts) }),
		),
		fyne.NewMenu("About",
			fyne.NewMenuItem("License", func() { displayLicense(hkPasswordm) }),
			fyne.NewMenuItem("Used Dependency Licenses", func() { displayDependencyLicences(hkPasswordm) }),
		),
	)

	mainWindow.SetMainMenu(menu)

	// bottom left (account listing)

	accountList := widget.NewListWithData(boundAccounts,
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(i binding.DataItem, o fyne.CanvasObject) {
			o.(*widget.Label).Bind(i.(binding.String))
		},
	)

	// top left (pagination and adding accounts)
	pastPage := widget.NewButton("<", func() { pageLeft(boundPage, boundAccounts) })
	setPage := widget.NewLabelWithData(binding.IntToString(boundPage))
	nextPage := widget.NewButton(">", func() { pageRight(boundPage, boundAccounts) })

	loadingBar := widget.NewProgressBarInfinite()
	loadingBar.Hide()

	addAccount := widget.NewButton("+", func() { addAccount(mainWindow, boundAccounts) })

	pagination := container.New(layout.NewHBoxLayout(), pastPage, setPage, nextPage)

	topLeft := container.NewBorder(nil, nil, pagination, addAccount, loadingBar)

	// top right (searching for specific account)
	searchField := widget.NewEntry()
	searchButton := widget.NewButton("", func() { searchAccount(mainWindow, boundAccounts, searchField, accountList) })
	searchButton.SetIcon(theme.SearchIcon())

	topRight := container.NewBorder(nil, nil, nil, searchButton, searchField)

	leftItems := container.NewBorder(topLeft, nil, nil, nil, accountList)

	// bottom right (selected account details)
	accountDisplay := widget.NewLabel("No account currently selected!")
	accountUsername := widget.NewEntry()
	accountPassword := widget.NewPasswordEntry()

	accountModify := widget.NewButton("Modify Account Data", func() {
		modifyAccount(mainWindow, accountDisplay.Text, accountUsername.Text, accountPassword.Text)
	})
	accountDelete := widget.NewButton("Delete Account", func() {
		deleteAccount(mainWindow, boundAccounts, accountDisplay.Text, accountList)
	})
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
		showAccountData(mainWindow, id, listAccs, accountDisplay, accountUsername, accountPassword, accountDetailsWithActions)
	}

	rightItems := container.New(layout.NewVBoxLayout(), topRight, layout.NewSpacer(), accountDetailsWithActions, layout.NewSpacer())

	mainGrid := container.New(layout.NewAdaptiveGridLayout(2), leftItems, rightItems)
	mainWindow.SetContent(mainGrid)

	mainWindow.ShowAndRun()
}
