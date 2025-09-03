from django.core.management.base import BaseCommand, CommandError
from django.core.exceptions import ValidationError
from ip_tracking.models import BlockedIP
import ipaddress

class Command(BaseCommand):
    """
    Django management command to block/unblock IP addresses.
    
    Usage:
        python3 manage.py block_ip --add 192.168.1.100 --reason "Brute force attack"
        python3 manage.py block_ip --remove 192.168.1.100
        python3 manage.py block_ip --list
        python3 manage.py block_ip --add 203.45.67.89 --reason "Spam bot"
        
    """
    help = 'Manage blocked IPs'
    
    def add_arguments(self,parser):
        """ 
        Define command line arguments this command accepts
        
        """
        # Create mutually exclusive group - user can only choose one action
        group = parser.add_mutually_exclusive_group(required=True)
        
        # add IP to blocklist
        group.add_argument(
            '--add',
            type=str,
            help='IP address to block (e.g., 192.168.1.100 or 2001:db8::1)'
        )
        # remove IP from blocklist
        group.add_argument(
            '--remove',
            type=str,
            help='IP to unblock'
        )
        # list all blocked IPs
        group.add_argument(
            '--list',
            action='store_true',
            help='list all currently blocked IPs'
        )
        # reason for blocking,should be used when --add is used
        parser.add_argument(
            '--reason',
            type=str,
            default='',
            help='reason for blocking this IP'
        )
    
    def validate_ip_address(self,ip_string):
        """
        Using Python's ipaddress module for robust validation,
        This catches malformed IPs before they hit the database
        
        """
        try:
            # this raises value error if IP is invalid
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False
    
    def handle(self,*args,**options):
        """
        Main command logic. Called when user runs the management command.
        
        Django calls this method with parsed command line arguments
        in the 'options' dictionary.
        
        """
        if options['add']:
            ip_to_block = options['add'].strip()
            reason = options['reason']
            
            # Validate IP format before attempting database operations
            if not self.validate_ip_address(ip_to_block):
                raise CommandError(f'Invalid IP address format: {ip_to_block}')
            
            # Check if IP is already blocked to avoid duplicate entries
            if BlockedIP.objects.filter(ip_address=ip_to_block).exists():
                self.stdout.write(
                    self.style.WARNING(f'IP {ip_to_block} is already blocked')
                )
                return
            
            # create new blocked IP entry
            try:
                blocked_ip = BlockedIP.objects.create(
                    ip_address=ip_to_block,
                    reason=reason
                )
                self.stdout.write(
                    self.style.SUCCESS(
                        f'Successfully blocked IP: {ip_to_block}'
                        + (f' (Reason: {reason})' if reason else '')
                    )
                )
            except ValidationError as e:
                raise CommandError(f'Database validation error: {e}')
        elif options['remove']:
            # Unblock an IP address
            ip_to_unblock = options['remove'].strip()
            
            # Validate IP format
            if not self.validate_ip_address(ip_to_unblock):
                raise CommandError(f'Invalid IP address format: {ip_to_unblock}')
            
            # Try to find and delete the blocked IP
            try:
                blocked_ip = BlockedIP.objects.get(ip_address=ip_to_unblock)
                blocked_ip.delete()
                
                self.stdout.write(
                    self.style.SUCCESS(f'Successfully unblocked IP: {ip_to_unblock}')
                )
                
            except BlockedIP.DoesNotExist:
                self.stdout.write(
                    self.style.WARNING(f'IP {ip_to_unblock} was not in blocklist')
                )
        
        elif options['list']:
            # List all currently blocked IPs
            blocked_ips = BlockedIP.objects.all().order_by('-created_at')
            
            if not blocked_ips.exists():
                self.stdout.write('No IPs are currently blocked.')
                return
            
            self.stdout.write(f'\nCurrently blocked IPs ({blocked_ips.count()}):\n')
            self.stdout.write('-' * 60)
            
            for blocked_ip in blocked_ips:
                # Format the output nicely
                blocked_time = blocked_ip.created_at.strftime('%Y-%m-%d %H:%M:%S')
                reason_text = f' - {blocked_ip.reason}' if blocked_ip.reason else ''
                
                self.stdout.write(
                    f'{blocked_ip.ip_address:15} | {blocked_time}{reason_text}'
                )