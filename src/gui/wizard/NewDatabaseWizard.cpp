/*
 *  Copyright (C) 2018 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "NewDatabaseWizard.h"
#include "NewDatabaseWizardPageEncryption.h"
#include "NewDatabaseWizardPageMasterKey.h"
#include "NewDatabaseWizardPageMetaData.h"

#include "core/Database.h"
#include "core/Global.h"
#include "core/Group.h"
#include "core/Resources.h"
#include "format/KeePass2.h"

#include <QVBoxLayout>

NewDatabaseWizard::NewDatabaseWizard(QWidget* parent)
    : QWizard(parent)
    , m_pages()
{
    setWizardStyle(QWizard::MacStyle);
    setOption(QWizard::WizardOption::HaveHelpButton, false);
    setOption(QWizard::WizardOption::NoDefaultButton, false); // Needed for macOS

    // clang-format off
    m_pages << new NewDatabaseWizardPageMetaData()
            << new NewDatabaseWizardPageEncryption()
            << new NewDatabaseWizardPageMasterKey();
    // clang-format on

    for (const auto& page : asConst(m_pages)) {
        addPage(page);
    }

    setWindowTitle(tr("Create a new KeePassXC database..."));

    Q_INIT_RESOURCE(wizard);
    setPixmap(QWizard::BackgroundPixmap, QPixmap(":/wizard/background-pixmap.png"));
}

NewDatabaseWizard::~NewDatabaseWizard()
{
}

bool NewDatabaseWizard::validateCurrentPage()
{
    return m_pages[currentId()]->validatePage();
}

/**
 * Take configured database and reset internal pointer.
 *
 * @return the configured database
 */
QSharedPointer<Database> NewDatabaseWizard::takeDatabase()
{
    auto tmpPointer = m_db;
    m_db.reset();
    return tmpPointer;
}

void NewDatabaseWizard::initializePage(int id)
{
    if (id == startId()) {
        m_db = QSharedPointer<Database>::create();
        m_db->rootGroup()->setName(tr("Root", "Root group"));
        m_db->setKdf({});
        m_db->setKey({});
    }

    m_pages[id]->setDatabase(m_db);
    m_pages[id]->initializePage();
}
