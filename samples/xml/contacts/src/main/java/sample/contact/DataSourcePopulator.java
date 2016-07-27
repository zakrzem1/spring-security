/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.contact;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.*;

import javax.sql.DataSource;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.acls.domain.AclImpl;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/**
 * Populates the Contacts in-memory database with contact and ACL information.
 * @author Ben Alex
 */
public class DataSourcePopulator implements InitializingBean {
	// ~ Instance fields
	// ================================================================================================
	JdbcTemplate template;
	private MutableAclService mutableAclService;
	final Random rnd = new Random();
	TransactionTemplate tt;
	final String[] firstNames =
		{ "Bob", "Mary", "James", "Jane", "Kristy", "Kirsty", "Kate", "Jeni", "Angela", "Melanie", "Kent", "William",
			"Geoff", "Jeff", "Adrian", "Amanda", "Lisa", "Elizabeth", "Prue", "Richard", "Darin", "Phillip", "Michael",
			"Belinda", "Samantha", "Brian", "Greg", "Matthew" };
	final String[] lastNames =
		{ "Smith", "Williams", "Jackson", "Rictor", "Nelson", "Fitzgerald", "McAlpine", "Sutherland", "Abbott", "Hall",
			"Edwards", "Gates", "Black", "Brown", "Gray", "Marwell", "Booch", "Johnson", "McTaggart", "Parklin",
			"Findlay", "Robinson", "Giugni", "Lang", "Chi", "Carmichael" };
	final String[] userNames = {

	};
	private int noOfContacts = 10000;
	private static final int NO_OF_USERS = 100;
	private int batchSize = 1000;

	// ~ Methods
	// ========================================================================================================

	public void afterPropertiesSet() throws Exception {
		System.out.println("Populating db");
		Assert.notNull(mutableAclService, "mutableAclService required");
		Assert.notNull(template, "dataSource required");
		Assert.notNull(tt, "platformTransactionManager required");

		// Set a user account that will initially own all the created data
		Authentication authRequest =
			new UsernamePasswordAuthenticationToken("rod", "koala", AuthorityUtils.createAuthorityList("ROLE_IGNORED"));
		SecurityContextHolder.getContext().setAuthentication(authRequest);

		dropTables(template,
			new String[] { "CONTACTS", "AUTHORITIES", "USERS", "ACL_ENTRY", "ACL_OBJECT_IDENTITY", "ACL_CLASS",
				"ACL_SID" });

		//		createAclTablesHsqlDb(template);
		System.out.println("Creating tables");
		createAclTablesPostgres(template);
		template.execute(
			"CREATE TABLE USERS(USERNAME VARCHAR(50) NOT NULL PRIMARY KEY,PASSWORD VARCHAR(500) NOT NULL,ENABLED BOOLEAN NOT NULL);");
		template.execute(
			"CREATE TABLE AUTHORITIES(USERNAME VARCHAR(50) NOT NULL,AUTHORITY VARCHAR(50) NOT NULL,CONSTRAINT FK_AUTHORITIES_USERS FOREIGN KEY(USERNAME) REFERENCES USERS(USERNAME));");
		template.execute("CREATE UNIQUE INDEX IX_AUTH_USERNAME ON AUTHORITIES(USERNAME,AUTHORITY);");

		template.execute(
			"CREATE TABLE CONTACTS(ID BIGINT NOT NULL PRIMARY KEY, CONTACT_NAME VARCHAR(50) NOT NULL, EMAIL VARCHAR(50) NOT NULL)");

		/*
		 * Passwords encoded using MD5, NOT in Base64 format, with null as salt Encoded
		 * password for rod is "koala" Encoded password for dianne is "emu" Encoded
		 * password for scott is "wombat" Encoded password for peter is "opal" (but user
		 * is disabled) Encoded password for bill is "wombat" Encoded password for bob is
		 * "wombat" Encoded password for jane is "wombat"
		 */
		template.execute(
			"INSERT INTO USERS VALUES('rod','$2a$10$75pBjapg4Nl8Pzd.3JRnUe7PDJmk9qBGwNEJDAlA3V.dEJxcDKn5O',TRUE);");
		template.execute(
			"INSERT INTO USERS VALUES('dianne','$2a$04$bCMEyxrdF/7sgfUiUJ6Ose2vh9DAMaVBldS1Bw2fhi1jgutZrr9zm',TRUE);");
		template.execute(
			"INSERT INTO USERS VALUES('scott','$2a$06$eChwvzAu3TSexnC3ynw4LOSw1qiEbtNItNeYv5uI40w1i3paoSfLu',TRUE);");
		template.execute(
			"INSERT INTO USERS VALUES('peter','$2a$04$8.H8bCMROLF4CIgd7IpeQ.tcBXLP5w8iplO0n.kCIkISwrIgX28Ii',FALSE);");
		template.execute(
			"INSERT INTO USERS VALUES('bill','$2a$04$8.H8bCMROLF4CIgd7IpeQ.3khQlPVNWbp8kzSQqidQHGFurim7P8O',TRUE);");
		template.execute(
			"INSERT INTO USERS VALUES('bob','$2a$06$zMgxlMf01SfYNcdx7n4NpeFlAGU8apCETz/i2C7VlYWu6IcNyn4Ay',TRUE);");
		template.execute(
			"INSERT INTO USERS VALUES('jane','$2a$05$ZrdS7yMhCZ1J.AAidXZhCOxdjD8LO/dhlv4FJzkXA6xh9gdEbBT/u',TRUE);");

		template.execute("INSERT INTO AUTHORITIES VALUES('rod','ROLE_USER');");
		template.execute("INSERT INTO AUTHORITIES VALUES('rod','ROLE_SUPERVISOR');");
		template.execute("INSERT INTO AUTHORITIES VALUES('dianne','ROLE_USER');");
		template.execute("INSERT INTO AUTHORITIES VALUES('scott','ROLE_USER');");
		template.execute("INSERT INTO AUTHORITIES VALUES('peter','ROLE_USER');");
		template.execute("INSERT INTO AUTHORITIES VALUES('bill','ROLE_USER');");
		template.execute("INSERT INTO AUTHORITIES VALUES('bob','ROLE_USER');");
		template.execute("INSERT INTO AUTHORITIES VALUES('jane','ROLE_USER');");
		List<String> users = new ArrayList(NO_OF_USERS);
		users.add("bill");
		users.add("bob");
		users.add("jane"); // don't want to mess around with
		System.out.println("Inserting users");
		for (int i = 0; i < NO_OF_USERS; i++) {
			String userId = "j" + i;
			users.add(userId);
			template.execute("INSERT INTO USERS VALUES('" + userId + "','$2a$05$ZrdS7yMhCZ1J"
				+ ".AAidXZhCOxdjD8LO/dhlv4FJzkXA6xh9gdEbBT/u',TRUE);");
			template.execute("INSERT INTO AUTHORITIES VALUES('" + userId + "','ROLE_USER');");
		}

		createContacts(Arrays.asList(new Contact(1L, "John Smith", "john@somewhere.com"),
			new Contact(2L, "Michael Citizen", "michael@xyz.com"), new Contact(3L, "Joe Bloggs", "joe@demo.com"),
			new Contact(4L, "Karen Sutherland", "karen@sutherland.com"),
			new Contact(5L, "Mitchell Howard", "mitchell@abcdef.com"), new Contact(6L, "Rose Costas", "rose@xyz.com"),
			new Contact(7L, "Amanda Smith", "amanda@abcdef.com"), new Contact(8L, "Cindy Smith", "cindy@smith.com"),
			new Contact(9L, "Jonathan Citizen", "jonathan@xyz.com")));
		System.out.println("Inserting contacts");
		LinkedList<Contact> contacts = new LinkedList<Contact>();
		long startTime = System.currentTimeMillis();
		long contactsCreated = 0;
		for (int i = 10; i < noOfContacts; i++) {
			String[] person = selectPerson();
			contacts.add(
				new Contact((long) i, person[2], person[0].toLowerCase() + "@" + person[1].toLowerCase() + ".com"));
			if (i % batchSize == 0) {
				createContacts(contacts);
				long batchTime = (System.currentTimeMillis() - startTime);
				contactsCreated += contacts.size();
				double creationRatio = contactsCreated * 1000 / batchTime;
				System.out.println("noOfContacts " + i + ", (" + creationRatio + " objs/s)");
				contacts = new LinkedList<Contact>();
			}
		}
		createContacts(contacts);

		// Now grant some permissions
		grantPermissions(1, "rod", BasePermission.ADMINISTRATION);

		grantPermissions(2, "rod", BasePermission.READ);

		grantPermissions(3, "rod", BasePermission.READ);
		grantPermissions(3, Arrays.asList(new PermissionForUser("rod", BasePermission.WRITE),
			new PermissionForUser("rod", BasePermission.DELETE)));

		grantPermissions(4, Arrays.asList(new PermissionForUser("rod", BasePermission.ADMINISTRATION),
			new PermissionForUser("dianne", BasePermission.ADMINISTRATION),
			new PermissionForUser("scott", BasePermission.READ)));

		grantPermissions(5, Arrays.asList(new PermissionForUser("dianne", BasePermission.ADMINISTRATION),
			new PermissionForUser("dianne", BasePermission.READ)));

		grantPermissions(6, Arrays.asList(new PermissionForUser("dianne", BasePermission.READ),
			new PermissionForUser("dianne", BasePermission.WRITE),
			new PermissionForUser("dianne", BasePermission.DELETE),
			new PermissionForUser("scott", BasePermission.READ)));

		grantPermissions(7, "scott", BasePermission.ADMINISTRATION);

		grantPermissions(8, Arrays.asList(new PermissionForUser("dianne", BasePermission.ADMINISTRATION),
			new PermissionForUser("dianne", BasePermission.READ), new PermissionForUser("scott", BasePermission.READ),
			new PermissionForUser("scott", BasePermission.ADMINISTRATION),
			new PermissionForUser("scott", BasePermission.READ), new PermissionForUser("scott", BasePermission.WRITE),
			new PermissionForUser("scott", BasePermission.DELETE)));

		// Now expressly change the owner of the first ten contacts
		// We have to do this last, because "rod" owns all of them (doing it sooner would
		// prevent ACL updates)
		// Note that ownership has no impact on permissions - they're separate (ownership
		// only allows ACl editing)
		changeOwner(5, "dianne");
		changeOwner(6, "dianne");
		changeOwner(7, "scott");
		changeOwner(8, "dianne");
		changeOwner(9, "scott");

		Permission[] permissions =
			new Permission[] { BasePermission.ADMINISTRATION, BasePermission.READ, BasePermission.WRITE,
				BasePermission.DELETE };

		// consistent sample data
		long permissionsStartTime = System.currentTimeMillis();
		long aclsProcessed = 0;

		Collection<PermissionForUser> permissionsForUsers;
		for (int i = 10; i < noOfContacts; i++) {
			permissionsForUsers = new LinkedList<PermissionForUser>();
			//System.out.println("Setting permissions for contact " + i);
			for (int userIdx = 1; userIdx < NO_OF_USERS; userIdx++) {
				String user = users.get(userIdx);
				Permission permission = permissions[rnd.nextInt(permissions.length)];
				permissionsForUsers.add(new PermissionForUser(user, permission));
			}
			grantPermissions(i, permissionsForUsers);
			aclsProcessed++;
			if (i % batchSize == 0) {
				double permRatio = aclsProcessed * 1000 / (System.currentTimeMillis() - permissionsStartTime);
				System.out.println("acls: " + i + ", ratio = " + permRatio + " acls/s");
			}
		}
		System.out.println(
			"zusammen ratio = " + (aclsProcessed * 1000 / (System.currentTimeMillis() - permissionsStartTime))
				+ " permissions/s");

		SecurityContextHolder.clearContext();
	}

	private void createContacts(final List<Contact> contacts) {
		//int i, String fullName, String email
		template.batchUpdate("INSERT INTO contacts VALUES (?, ?, ?) ", new BatchPreparedStatementSetter() {
			@Override
			public void setValues(PreparedStatement ps, int i) throws SQLException {
				ps.setLong(1, contacts.get(i).getId());
				ps.setString(2, contacts.get(i).getName());
				ps.setString(3, contacts.get(i).getEmail());
			}

			@Override
			public int getBatchSize() {
				return contacts.size();
			}
		});

		for (Contact contact : contacts) {
			createObjectIdentity(contact.getId().intValue());
		}
	}

	private void createObjectIdentity(int i) {
		final ObjectIdentity objectIdentity = new ObjectIdentityImpl(Contact.class, new Long(i));
		tt.execute(new TransactionCallback<Object>() {
			public Object doInTransaction(TransactionStatus arg0) {
				mutableAclService.createAcl(objectIdentity);

				return null;
			}
		});
	}

	private void dropTables(JdbcTemplate template, String[] strings) {
		for (int i = 0; i < strings.length; i++) {
			try {
				template.execute("DROP TABLE " + strings[i]);
			} catch (Exception e) {
				System.out.println("Failed to drop table " + strings[i] + ": " + e.getMessage());
			}
		}
	}

	private void createAclTablesPostgres(JdbcTemplate template) {
		template.execute(
			"create table acl_sid(\n" + "  id bigserial not null primary key,\n" + "  principal boolean not null,\n"
				+ "  sid varchar(100) not null,\n" + "  constraint unique_uk_1 unique(sid,principal));\n" + "\n"
				+ "create table acl_class(\n" + "  id bigserial not null primary key,\n"
				+ "  class varchar(100) not null,\n" + "  constraint unique_uk_2 unique(class));\n");

		template.execute("create table acl_object_identity(\n" + "  id bigserial primary key,\n"
			+ "  object_id_class bigint not null,\n" + "  object_id_identity bigint not null,\n"
			+ "  parent_object bigint,\n" + "  owner_sid bigint,\n" + "  entries_inheriting boolean not null,\n"
			+ "  constraint unique_uk_3 unique(object_id_class,object_id_identity),\n"
			+ "  constraint foreign_fk_1 foreign key(parent_object) references acl_object_identity(id),\n"
			+ "  constraint foreign_fk_2 foreign key(object_id_class) references acl_class(id),\n"
			+ "  constraint foreign_fk_3 foreign key(owner_sid) references acl_sid(id));\n");
		template.execute(
			"create table acl_entry(\n" + "  id bigserial primary key,\n" + "  acl_object_identity bigint not null,\n"
				+ "  ace_order int not null,\n" + "  sid bigint not null,\n" + "  mask integer not null,\n"
				+ "  granting boolean not null,\n" + "  audit_success boolean not null,\n"
				+ "  audit_failure boolean not null,\n"
				+ "  constraint unique_uk_4 unique(acl_object_identity,ace_order),\n"
				+ "  constraint foreign_fk_4 foreign key(acl_object_identity)\n"
				+ "      references acl_object_identity(id),\n"
				+ "  constraint foreign_fk_5 foreign key(sid) references acl_sid(id));");
	}

	private void createAclTablesHsqlDb(JdbcTemplate template) {
		template.execute(
			"CREATE TABLE ACL_SID(" + "ID BIGINT GENERATED BY DEFAULT AS IDENTITY(START WITH 100) NOT NULL PRIMARY KEY,"
				+ "PRINCIPAL BOOLEAN NOT NULL," + "SID VARCHAR_IGNORECASE(100) NOT NULL,"
				+ "CONSTRAINT UNIQUE_UK_1 UNIQUE(SID,PRINCIPAL));");
		template.execute("CREATE TABLE ACL_CLASS("
			+ "ID BIGINT GENERATED BY DEFAULT AS IDENTITY(START WITH 100) NOT NULL PRIMARY KEY,"
			+ "CLASS VARCHAR_IGNORECASE(100) NOT NULL," + "CONSTRAINT UNIQUE_UK_2 UNIQUE(CLASS));");
		template.execute("CREATE TABLE ACL_OBJECT_IDENTITY("
			+ "ID BIGINT GENERATED BY DEFAULT AS IDENTITY(START WITH 100) NOT NULL PRIMARY KEY,"
			+ "OBJECT_ID_CLASS BIGINT NOT NULL," + "OBJECT_ID_IDENTITY BIGINT NOT NULL," + "PARENT_OBJECT BIGINT,"
			+ "OWNER_SID BIGINT," + "ENTRIES_INHERITING BOOLEAN NOT NULL,"
			+ "CONSTRAINT UNIQUE_UK_3 UNIQUE(OBJECT_ID_CLASS,OBJECT_ID_IDENTITY),"
			+ "CONSTRAINT FOREIGN_FK_1 FOREIGN KEY(PARENT_OBJECT)REFERENCES ACL_OBJECT_IDENTITY(ID),"
			+ "CONSTRAINT FOREIGN_FK_2 FOREIGN KEY(OBJECT_ID_CLASS)REFERENCES ACL_CLASS(ID),"
			+ "CONSTRAINT FOREIGN_FK_3 FOREIGN KEY(OWNER_SID)REFERENCES ACL_SID(ID));");
		template.execute("CREATE TABLE ACL_ENTRY("
			+ "ID BIGINT GENERATED BY DEFAULT AS IDENTITY(START WITH 100) NOT NULL PRIMARY KEY,"
			+ "ACL_OBJECT_IDENTITY BIGINT NOT NULL,ACE_ORDER INT NOT NULL,SID BIGINT NOT NULL,"
			+ "MASK INTEGER NOT NULL,GRANTING BOOLEAN NOT NULL,AUDIT_SUCCESS BOOLEAN NOT NULL,"
			+ "AUDIT_FAILURE BOOLEAN NOT NULL,CONSTRAINT UNIQUE_UK_4 UNIQUE(ACL_OBJECT_IDENTITY,ACE_ORDER),"
			+ "CONSTRAINT FOREIGN_FK_4 FOREIGN KEY(ACL_OBJECT_IDENTITY) REFERENCES ACL_OBJECT_IDENTITY(ID),"
			+ "CONSTRAINT FOREIGN_FK_5 FOREIGN KEY(SID) REFERENCES ACL_SID(ID));");
	}

	private void changeOwner(int contactNumber, String newOwnerUsername) {
		AclImpl acl =
			(AclImpl) mutableAclService.readAclById(new ObjectIdentityImpl(Contact.class, new Long(contactNumber)));
		acl.setOwner(new PrincipalSid(newOwnerUsername));
		updateAclInTransaction(acl);
	}

	public int getNoOfContacts() {
		return noOfContacts;
	}

	private void grantPermissions(int i, String rod, Permission administration) {
		grantPermissions(i, Arrays.asList(new PermissionForUser(rod, administration)));
	}

	private void grantPermissions(int contactNumber, Collection<PermissionForUser> permissionsForUsers) {
		AclImpl acl =
			(AclImpl) mutableAclService.readAclById(new ObjectIdentityImpl(Contact.class, (long) contactNumber));
		for (PermissionForUser userPermission : permissionsForUsers) {
			acl.insertAce(acl.getEntries().size(), userPermission.getPermission(),
				new PrincipalSid(userPermission.getRecipientUsername()), true);
		}
		updateAclInTransaction(acl);
	}

	private String[] selectPerson() {
		String firstName = firstNames[rnd.nextInt(firstNames.length)];
		String lastName = lastNames[rnd.nextInt(lastNames.length)];

		return new String[] { firstName, lastName, firstName + " " + lastName };
	}

	public void setNoOfContacts(int noOfContacts) {
		this.noOfContacts = noOfContacts;
	}

	public void setDataSource(DataSource dataSource) {
		System.out.println(dataSource.toString());
		this.template = new JdbcTemplate(dataSource);
	}

	public void setMutableAclService(MutableAclService mutableAclService) {
		this.mutableAclService = mutableAclService;
	}

	public void setPlatformTransactionManager(PlatformTransactionManager platformTransactionManager) {
		this.tt = new TransactionTemplate(platformTransactionManager);
	}

	private void updateAclInTransaction(final MutableAcl acl) {
		tt.execute(new TransactionCallback<Object>() {
			public Object doInTransaction(TransactionStatus arg0) {
				mutableAclService.updateAcl(acl);

				return null;
			}
		});
	}

	private class PermissionForUser {
		String recipientUsername;
		Permission permission;

		public PermissionForUser(String recipientUsername, Permission permission) {
			this.recipientUsername = recipientUsername;
			this.permission = permission;
		}

		public String getRecipientUsername() {
			return recipientUsername;
		}

		public Permission getPermission() {
			return permission;
		}
	}
}
