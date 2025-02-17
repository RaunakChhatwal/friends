use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mut profiles_foreign_key = ForeignKey::create()
            .from(User::Table, User::Profile)
            .to(Profile::Table, Profile::Id)
            .on_delete(ForeignKeyAction::Cascade)
            .to_owned();

        let users = Table::create()
            .table(User::Table)
            .if_not_exists()
            .col(pk_auto(User::Id))
            .col(uuid_uniq(User::UUID))
            .col(string_uniq(User::Username))
            .col(string(User::PasswordHash))
            .col(integer_uniq(User::Profile))
            .foreign_key(&mut profiles_foreign_key)
            .to_owned();

        let idx_users_username = Index::create()
            .name("idx_users_username")
            .table(User::Table)
            .col(User::Username)
            .to_owned();

        let mut users_foreign_key = ForeignKey::create()
            .from(Profile::Table, Profile::User)
            .to(User::Table, User::Id)
            .on_delete(ForeignKeyAction::Cascade)
            .to_owned();

        let profiles = Table::create()
            .table(Profile::Table)
            .if_not_exists()
            .col(pk_auto(Profile::Id))
            .col(string(Profile::Bio))
            .col(date(Profile::DateOfBirth))
            .col(string(Profile::City))
            .col(integer_uniq(Profile::User))
            .foreign_key(&mut users_foreign_key)
            .to_owned();

        manager.create_table(users).await?;
        manager.create_index(idx_users_username).await?;
        manager.create_table(profiles).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(User::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(Profile::Table).to_owned()).await
    }
}

#[derive(DeriveIden)]
enum User {
    Table,
    Id,
    UUID,
    Username,
    PasswordHash,
    Profile,
}

#[derive(DeriveIden)]
enum Profile {
    Table,
    Id,
    Bio,
    DateOfBirth,
    City,
    User,
}
